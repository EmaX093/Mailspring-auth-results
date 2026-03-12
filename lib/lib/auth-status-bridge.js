"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mailspring_exports_1 = require("mailspring-exports");
class AuthStatusBridge extends mailspring_exports_1.React.Component {
    render() {
        const { message } = this.props;
        const authHeader = message.getHeader('Authentication-Results') || "";
        // Función para extraer el estado de cada parámetro
        const getStatus = (key) => {
            const regex = new RegExp(`${key}=(\\w+)`, 'i');
            const match = regex.exec(authHeader);
            return match ? match[1].toLowerCase() : 'none';
        };
        const results = {
            dkim: getStatus('dkim'),
            spf: getStatus('spf'),
            dmarc: getStatus('dmarc'),
        };
        // Verificamos si los 3 pasaron la validación
        const isFullyVerified = results.dkim === 'pass' &&
            results.spf === 'pass' &&
            results.dmarc === 'pass';
        const getStyle = (status) => ({
            color: status === 'pass' ? '#28a745' : (status === 'fail' ? '#dc3545' : '#8c8c8c'),
            fontSize: '11px',
            marginRight: '10px',
            fontWeight: '600',
            display: 'inline-flex',
            alignItems: 'center',
            padding: '2px 4px',
            borderRadius: '3px',
            backgroundColor: 'rgba(0,0,0,0.03)'
        });
        return (mailspring_exports_1.React.createElement("div", { style: { marginTop: '6px', marginBottom: '4px', display: 'flex', alignItems: 'center' } }, isFullyVerified && (mailspring_exports_1.React.createElement("div", { style: {
                color: '#1e7e34',
                marginRight: '12px',
                paddingRight: '12px',
                borderRight: '1px solid #ddd',
                display: 'flex',
                alignItems: 'center',
                fontWeight: 'bold',
                fontSize: '12px'
            } }, mailspring_exports_1.React.createElement("i", { className: "fa fa-shield", style: { marginRight: '5px' } }), "VERIFIED SENDER")), ['dkim', 'spf', 'dmarc'].map(key => (mailspring_exports_1.React.createElement("span", { key: key, style: getStyle(results[key]), title: `Auth result: ${results[key]}` }, mailspring_exports_1.React.createElement("i", { className: `fa ${results[key] === 'pass' ? 'fa-lock' : 'fa-unlock-alt'}`, style: { marginRight: '4px' } }), key.toUpperCase())))));
    }
}
exports.default = AuthStatusBridge;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC1zdGF0dXMtYnJpZGdlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vYXV0aC1zdGF0dXMtYnJpZGdlLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLFlBQVksQ0FBQztBQUNiLE1BQU0sQ0FBQyxjQUFjLENBQUMsT0FBTyxFQUFFLFlBQVksRUFBRSxFQUFFLEtBQUssRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0FBQzlELE1BQU0sb0JBQW9CLEdBQUcsT0FBTyxDQUFDLG9CQUFvQixDQUFDLENBQUM7QUFDM0QsTUFBTSxnQkFBaUIsU0FBUSxvQkFBb0IsQ0FBQyxLQUFLLENBQUMsU0FBUztJQUMvRCxNQUFNO1FBQ0YsTUFBTSxFQUFFLE9BQU8sRUFBRSxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUM7UUFDL0IsTUFBTSxVQUFVLEdBQUcsT0FBTyxDQUFDLFNBQVMsQ0FBQyx3QkFBd0IsQ0FBQyxJQUFJLEVBQUUsQ0FBQztRQUNyRSxtREFBbUQ7UUFDbkQsTUFBTSxTQUFTLEdBQUcsQ0FBQyxHQUFHLEVBQUUsRUFBRTtZQUN0QixNQUFNLEtBQUssR0FBRyxJQUFJLE1BQU0sQ0FBQyxHQUFHLEdBQUcsU0FBUyxFQUFFLEdBQUcsQ0FBQyxDQUFDO1lBQy9DLE1BQU0sS0FBSyxHQUFHLEtBQUssQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUM7WUFDckMsT0FBTyxLQUFLLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDO1FBQ25ELENBQUMsQ0FBQztRQUNGLE1BQU0sT0FBTyxHQUFHO1lBQ1osSUFBSSxFQUFFLFNBQVMsQ0FBQyxNQUFNLENBQUM7WUFDdkIsR0FBRyxFQUFFLFNBQVMsQ0FBQyxLQUFLLENBQUM7WUFDckIsS0FBSyxFQUFFLFNBQVMsQ0FBQyxPQUFPLENBQUM7U0FDNUIsQ0FBQztRQUNGLDZDQUE2QztRQUM3QyxNQUFNLGVBQWUs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