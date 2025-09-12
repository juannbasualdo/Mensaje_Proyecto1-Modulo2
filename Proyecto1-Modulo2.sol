///SPDX-License-Identifier: MIT 
pragma solidity 0.8.26;

/** 
 * @title Contrato Mensaje 
 * @author i3arba - 77 Innovation Labs 
 * @notice Este contrato es parte del primer proyecto del Ethereum Developer Pack 
 * @custom:security Este es un contrato educativo y no debe ser usado en producción 
 */ 
contract Mensaje {
	/*////////////////////////
				Variables de Estado
	////////////////////////*/
	///@notice variable para almacenar mensajes
	string s_mensaje;
	
	/*////////////////////////
					Eventos
	////////////////////////*/
	///@notice evento emitido cuando el mensaje es actualizado
	event Mensaje_MensajeActualizado(string mensaje);
	
	/*////////////////////////
					Funciones
	////////////////////////*/
	/*
		@notice Función utilizada para almacenar un mensaje en la blockchain
		@param _mensaje entrada del tipo string
	*/
	function setMensaje(string memory _mensaje) external {
		s_mensaje = _mensaje;
		
		emit Mensaje_MensajeActualizado(_mensaje);
	}

	/*
		*@notice función get para devolver el mensaje almacenado
		*@return _mensaje almacenado
	*/
	function getMensaje() public view returns(string memory mensaje_){
		mensaje_ = s_mensaje;
	}
}