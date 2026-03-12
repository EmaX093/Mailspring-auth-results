"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const mailspring_exports_1 = require("mailspring-exports");
const auth_status_bridge_1 = __importDefault(require("./auth-status-bridge"));
// Forzamos el nombre antes de registrar
auth_status_bridge_1.default.displayName = 'AuthStatusBridge';
function activate() {
    mailspring_exports_1.ComponentRegistry.register(auth_status_bridge_1.default, {
        role: 'MessageHeader',
    });
}
exports.activate = activate;
function deactivate() {
    mailspring_exports_1.ComponentRegistry.unregister(auth_status_bridge_1.default);
}
exports.deactivate = deactivate;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWFpbi5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3NyYy9tYWluLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsMkRBQXVEO0FBQ3ZELDhFQUFvRDtBQUVwRCx3Q0FBd0M7QUFDeEMsNEJBQWdCLENBQUMsV0FBVyxHQUFHLGtCQUFrQixDQUFDO0FBRWxELFNBQWdCLFFBQVE7SUFDdEIsc0NBQWlCLENBQUMsUUFBUSxDQUFDLDRCQUFnQixFQUFFO1FBQzNDLElBQUksRUFBRSxlQUFlO0tBQ3RCLENBQUMsQ0FBQztBQUNMLENBQUM7QUFKRCw0QkFJQztBQUVELFNBQWdCLFVBQVU7SUFDeEIsc0NBQWlCLENBQUMsVUFBVSxDQUFDLDRCQUFnQixDQUFDLENBQUM7QUFDakQsQ0FBQztBQUZELGdDQUVDIn0=