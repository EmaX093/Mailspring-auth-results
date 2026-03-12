"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const mailspring_exports_1 = require("mailspring-exports");
const auth_status_bridge_1 = __importDefault(require("../lib/auth-status-bridge"));
function activate() {
    // Registramos el componente en la zona de "Bonus" del header del mensaje
    mailspring_exports_1.ComponentRegistry.register(auth_status_bridge_1.default, {
        role: 'MessageHeaderBonus',
    });
}
exports.activate = activate;
function deactivate() {
    mailspring_exports_1.ComponentRegistry.unregister(auth_status_bridge_1.default);
}
exports.deactivate = deactivate;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWFpbi5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9tYWluLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsMkRBQXFEO0FBQ3JELG1GQUF5RDtBQUV6RCxTQUFnQixRQUFRO0lBQ3RCLHlFQUF5RTtJQUN6RSxzQ0FBaUIsQ0FBQyxRQUFRLENBQUMsNEJBQWdCLEVBQUU7UUFDM0MsSUFBSSxFQUFFLG9CQUFvQjtLQUMzQixDQUFDLENBQUM7QUFDTCxDQUFDO0FBTEQsNEJBS0M7QUFFRCxTQUFnQixVQUFVO0lBQ3hCLHNDQUFpQixDQUFDLFVBQVUsQ0FBQyw0QkFBZ0IsQ0FBQyxDQUFDO0FBQ2pELENBQUM7QUFGRCxnQ0FFQyJ9