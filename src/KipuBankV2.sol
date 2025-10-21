// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Extensión común de metadatos para leer `decimals()` en muchos ERC20.
interface IERC20Metadata is IERC20 {
    function decimals() external view returns (uint8);
}

/// @dev Interfaz mínima de Chainlink AggregatorV3 (TOKEN/USD).
interface AggregatorV3Interface {
    function decimals() external view returns (uint8);
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

/// @dev Estructura de configuración por token. Almacena parámetros
///      necesarios para depósitos/retiros y cálculos en USD
struct TokenConfig {
    bool supported;         // Indica si el token está habilitado.
    bool isNative;          // True si es ETH (address(0)).
    uint8 tokenDecimals;    // Número de decimales del token.
    uint256 withdrawLimit;  // Límite por retiro (en unidades del token).
    address priceFeed;      // Dirección del agregador Chainlink TOKEN/USD.
}

/// @title KipuBankV2 (OpenZeppelin edition)
/// @notice Versión multi-token con control de acceso, bank cap en USD y conversión de decimales
/// @dev Usa `AccessControl` (roles) + `ReentrancyGuard` + `SafeERC20` + oráculos Chainlink
contract KipuBankV2 is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTES
    //////////////////////////////////////////////////////////////*/

    /// @notice Rol administrador. Puede configurar tokens y parámetros
    bytes32 public constant ROLE_ADMIN = keccak256("ROLE_ADMIN");

    /// @notice Identificador del token nativo (ETH). Uso address(0)
    address public constant NATIVE_TOKEN = address(0);

    /// @notice Decimales internos de USD estilo USDC (6 decimales)
    uint8 public constant USD_DECIMALS = 6;

    /*//////////////////////////////////////////////////////////////
                               ESTADO
    //////////////////////////////////////////////////////////////*/

    /// @notice Límite global del banco en USD (6 decimales). Inmutable
    uint256 public immutable bankCapUsd6;

    /// @notice Total acumulado en USD(6) depositado en el banco
    uint256 public totalDepositedUsd6;

    /// @notice Contadores de operaciones
    uint256 public depositCount;
    uint256 public withdrawCount;

    /// @notice Saldos: balances[token][usuario] en unidades nativas del token
    mapping(address => mapping(address => uint256)) private balances;

    /// @notice Configuración por token. address(0) = ETH
    mapping(address => TokenConfig) public tokenConfig;

    /*//////////////////////////////////////////////////////////////
                               ERRORES
    //////////////////////////////////////////////////////////////*/

    error ZeroAmount();                     // Monto igual a cero
    error UnsupportedToken(address token);  // Token no soportado o inválido
    error PriceFeedNotSet(address token);   // Oráculo no configurado
    error PriceNegative();                  // Precio inválido (<= 0)
    error CapExceeded(uint256 attempted, uint256 cap);                 // Se supera el cap global
    error WithdrawLimitExceeded(uint256 attempted, uint256 limit);      // Mayor al límite por retiro.
    error InsufficientBalance(uint256 balance, uint256 needed);         // Saldo insuficiente
    error EthTransferFailed();                                         // Fallo al transferir ETH

    /*//////////////////////////////////////////////////////////////
                               EVENTOS
    //////////////////////////////////////////////////////////////*/

    event TokenConfigured(
        address indexed token,
        bool supported,
        bool isNative,
        uint8 tokenDecimals,
        uint256 withdrawLimit,
        address priceFeed
    );

    event Deposit(
        address indexed token,
        address indexed account,
        uint256 amountToken,
        uint256 newBalanceToken,
        uint256 amountUsd6
    );

    event Withdraw(
        address indexed token,
        address indexed account,
        uint256 amountToken,
        uint256 newBalanceToken,
        uint256 amountUsd6
    );

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _bankCapUsd6 Cap global del banco en USD con 6 decimales
    /// @param ethPriceFeed Dirección del oráculo Chainlink ETH/USD
    /// @param ethWithdrawLimit Límite por retiro en ETH (en wei)
    constructor(
        uint256 _bankCapUsd6,
        address ethPriceFeed,
        uint256 ethWithdrawLimit
    ) {
        if (_bankCapUsd6 == 0) revert ZeroAmount();


        bankCapUsd6 = _bankCapUsd6;

        // Otorgar roles al deployer:
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender); // super-admin para poder dar/quitar roles si hiciera falta
        _grantRole(ROLE_ADMIN, msg.sender);         // admin operativo del contrato

        // Configurar ETH (NATIVE_TOKEN)
        TokenConfig memory cfg;
        cfg.supported = true;
        cfg.isNative = true;
        cfg.tokenDecimals = 18;

        cfg.withdrawLimit = ethWithdrawLimit;
        cfg.priceFeed = ethPriceFeed;
        tokenConfig[NATIVE_TOKEN] = cfg;

        emit TokenConfigured(NATIVE_TOKEN, true, true, 18, ethWithdrawLimit, ethPriceFeed);
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Exige que el monto sea > 0 (para depósitos/retiros)
    modifier nonZero(uint256 amount) {
        if (amount == 0) revert ZeroAmount();
        _;
    }

    /// @notice Exige que el token esté soportado (habilitado)
    modifier tokenSupported(address token) {
        if (!tokenConfig[token].supported) revert UnsupportedToken(token);
        _;
    }

    /// @notice Exige que el token NO sea ETH (para funciones que esperan ERC-20)
    modifier notNative(address token) {
        if (token == NATIVE_TOKEN) revert UnsupportedToken(token);
        _;
    }

    /// @notice Exige que el retiro no supere el límite por transacción del token.
    modifier underWithdrawLimit(address token, uint256 amount) {
        TokenConfig memory cfg = tokenConfig[token];
        if (amount > cfg.withdrawLimit) revert WithdrawLimitExceeded(amount, cfg.withdrawLimit);
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURACIÓN DE TOKENS
    //////////////////////////////////////////////////////////////*/

    /// @notice Agrega o actualiza un token ERC-20 soportado
    /// @dev Solo `ROLE_ADMIN`
    function setTokenConfig(
        address token,
        bool supported,
        uint8 tokenDecimals,
        uint256 withdrawLimit,
        address priceFeed
    ) external onlyRole(ROLE_ADMIN) {
        if (token == NATIVE_TOKEN) revert UnsupportedToken(token);

        TokenConfig storage cfg = tokenConfig[token];
        cfg.supported   = supported;
        cfg.isNative    = false;

        // Si tokenDecimals es 0, intentar leer `decimals()` directamente del token.
        if (tokenDecimals == 0) {
            // `try/catch` evita revertir si el token no implementa `decimals()`.
            try IERC20Metadata(token).decimals() returns (uint8 dec) {
                cfg.tokenDecimals = dec;
            } catch {
                // Si no implementa decimals(), asumir 18 (lo más común).
                cfg.tokenDecimals = 18;
            }
        } else {
            cfg.tokenDecimals = tokenDecimals;
        }

        cfg.withdrawLimit = withdrawLimit;
        cfg.priceFeed     = priceFeed;

        emit TokenConfigured(
            token,
            supported,
            false,
            cfg.tokenDecimals,
            withdrawLimit,
            priceFeed
        );
    }

    /*//////////////////////////////////////////////////////////////
                               DEPÓSITOS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposita ETH en tu bóveda personal
    /// @dev Suma el valor en USD(6) al total y verifica que no supere el cap global
    function depositEth()
        external
        payable
        nonReentrant
        nonZero(msg.value)
        tokenSupported(NATIVE_TOKEN)
    {
        // Calcular valor en USD(6) y verificar cap
        uint256 usd6 = _toUsd(NATIVE_TOKEN, msg.value);
        uint256 attemptedUsd = totalDepositedUsd6 + usd6;
        if (attemptedUsd > bankCapUsd6) revert CapExceeded(attemptedUsd, bankCapUsd6);

        // Effects
        balances[NATIVE_TOKEN][msg.sender] += msg.value;
        totalDepositedUsd6 = attemptedUsd;
        unchecked { depositCount++; }

        // Event
        emit Deposit(NATIVE_TOKEN, msg.sender, msg.value, balances[NATIVE_TOKEN][msg.sender], usd6);
    }

    /// @notice Deposita un token ERC-20 habilitado
    function depositToken(address token, uint256 amount)
        external
        nonReentrant
        nonZero(amount)
        notNative(token)
        tokenSupported(token)
    {
        // Calcular valor en USD(6) y verificar cap
        uint256 usd6 = _toUsd(token, amount);
        uint256 attemptedUsd = totalDepositedUsd6 + usd6;
        if (attemptedUsd > bankCapUsd6) revert CapExceeded(attemptedUsd, bankCapUsd6);

        // Effects
        balances[token][msg.sender] += amount;
        totalDepositedUsd6 = attemptedUsd;
        unchecked { depositCount++; }

        // Interactions (transferencia segura)
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Event
        emit Deposit(token, msg.sender, amount, balances[token][msg.sender], usd6);
    }

    /*//////////////////////////////////////////////////////////////
                                RETIROS
    //////////////////////////////////////////////////////////////*/

    /// @notice Retira ETH de tu bóveda personal.
    function withdrawEth(uint256 amount)
        external
        nonReentrant
        nonZero(amount)
        tokenSupported(NATIVE_TOKEN)
        underWithdrawLimit(NATIVE_TOKEN, amount)
    {
        uint256 userBal = balances[NATIVE_TOKEN][msg.sender];
        if (userBal < amount) revert InsufficientBalance(userBal, amount);

        // Effects
        balances[NATIVE_TOKEN][msg.sender] = userBal - amount;
        unchecked { withdrawCount++; }

        // Interactions (transferencia nativa segura)
        (bool sent, ) = msg.sender.call{value: amount}("");
        if (!sent) revert EthTransferFailed();

        emit Withdraw(NATIVE_TOKEN, msg.sender, amount, balances[NATIVE_TOKEN][msg.sender], _toUsd(NATIVE_TOKEN, amount));
    }

    /// @notice Retira un token ERC-20   habilitado
    function withdrawToken(address token, uint256 amount)
        external
        nonReentrant
        nonZero(amount)
        notNative(token)
        tokenSupported(token)
        underWithdrawLimit(token, amount)
    {
        uint256 userBal = balances[token][msg.sender];
        if (userBal < amount) revert InsufficientBalance(userBal, amount);

        // Effects
        balances[token][msg.sender] = userBal - amount;
        unchecked { withdrawCount++; }

        // Interactions  (transferencia segura)
        IERC20(token).safeTransfer(msg.sender, amount);

        emit Withdraw(token, msg.sender, amount, balances[token][msg.sender], _toUsd(token, amount));
    }

    /*//////////////////////////////////////////////////////////////
                                  VISTAS
    //////////////////////////////////////////////////////////////*/

    /// @notice Devuelve el saldo del remitente para un token (en unidades del token)
    function getBalance(address token) external view returns (uint256) {
        return balances[token][msg.sender];
    }

    /// @notice Devuelve el saldo de un usuario en USD(6) estimado para un token
    function getUsdBalance(address token, address user) external view returns (uint256) {
        uint256 amt = balances[token][user];
        return _toUsd(token, amt);
    }

    /*//////////////////////////////////////////////////////////////
                              FUNCIONES INTERNAS
    //////////////////////////////////////////////////////////////*/

    /// @dev Convierte un monto de `token` a USD con 6 decimales usando Chainlink
    function _toUsd(address token, uint256 amount) internal view returns (uint256 usd6) {
        if (amount == 0) return 0;
        TokenConfig memory cfg = tokenConfig[token];
        address feed = cfg.priceFeed;
        if (feed == address(0)) revert PriceFeedNotSet(token);

        // Obtener precio TOKEN/USD
        (, int256 price,, ,) = AggregatorV3Interface(feed).latestRoundData();
        if (price <= 0) revert PriceNegative();

        uint8 priceDecimals = AggregatorV3Interface(feed).decimals();

        // Multiplicar cantidad del token por su precio (ajustado al feed)
        uint256 numerator = amount * uint256(price);

        // Ajustar por decimales del feed → bajar a enteros
        if (priceDecimals > 0) {
            numerator = numerator / (10 ** priceDecimals);
        }

        // Ajustar por decimales del token a USD_DECIMALS (6)
        if (cfg.tokenDecimals >= USD_DECIMALS) {
            uint256 factor = 10 ** (cfg.tokenDecimals - USD_DECIMALS);
            usd6 = numerator / factor;
        } else {
            uint256 factor = 10 ** (USD_DECIMALS - cfg.tokenDecimals);
            usd6 = numerator * factor;
        }
    }
}
