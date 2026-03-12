import { ComponentRegistry } from 'mailspring-exports';
import AuthStatusBridge from './auth-status-bridge';

// Forzamos el nombre antes de registrar
AuthStatusBridge.displayName = 'AuthStatusBridge';

export function activate() {
  ComponentRegistry.register(AuthStatusBridge, {
    role: 'MessageHeader',
  });
}

export function deactivate() {
  ComponentRegistry.unregister(AuthStatusBridge);
}