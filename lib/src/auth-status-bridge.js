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
        return (mailspring_exports_1.React.createElement("div", { style: { marginTop: '6px', marginBottom: '4px', display: 'flex', alignItems: 'center' } },
            isFullyVerified && (mailspring_exports_1.React.createElement("div", { style: {
                    color: '#1e7e34',
                    marginRight: '12px',
                    paddingRight: '12px',
                    borderRight: '1px solid #ddd',
                    display: 'flex',
                    alignItems: 'center',
                    fontWeight: 'bold',
                    fontSize: '12px'
                } },
                mailspring_exports_1.React.createElement("i", { className: "fa fa-shield", style: { marginRight: '5px' } }),
                "VERIFIED SENDER")),
            ['dkim', 'spf', 'dmarc'].map(key => (mailspring_exports_1.React.createElement("span", { key: key, style: getStyle(results[key]), title: `Auth result: ${results[key]}` },
                mailspring_exports_1.React.createElement("i", { className: `fa ${results[key] === 'pass' ? 'fa-lock' : 'fa-unlock-alt'}`, style: { marginRight: '4px' } }),
                key.toUpperCase())))));
    }
}
exports.default = AuthStatusBridge;
// ESTO ES LO QUE FALTA PARA QUE EL REGISTRY NO TIRE ERROR:
AuthStatusBridge.displayName = 'AuthStatusBridge';
exports.default = AuthStatusBridge;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC1zdGF0dXMtYnJpZGdlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2F1dGgtc3RhdHVzLWJyaWRnZS5qc3giXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSwyREFBMkM7QUFFM0MsTUFBcUIsZ0JBQWlCLFNBQVEsMEJBQUssQ0FBQyxTQUFTO0lBQzNELE1BQU07UUFDSixNQUFNLEVBQUUsT0FBTyxFQUFFLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQztRQUMvQixNQUFNLFVBQVUsR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLHdCQUF3QixDQUFDLElBQUksRUFBRSxDQUFDO1FBRXJFLG1EQUFtRDtRQUNuRCxNQUFNLFNBQVMsR0FBRyxDQUFDLEdBQUcsRUFBRSxFQUFFO1lBQ3hCLE1BQU0sS0FBSyxHQUFHLElBQUksTUFBTSxDQUFDLEdBQUcsR0FBRyxTQUFTLEVBQUUsR0FBRyxDQUFDLENBQUM7WUFDL0MsTUFBTSxLQUFLLEdBQUcsS0FBSyxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQztZQUNyQyxPQUFPLEtBQUssQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUM7UUFDakQsQ0FBQyxDQUFDO1FBRUYsTUFBTSxPQUFPLEdBQUc7WUFDZCxJQUFJLEVBQUUsU0FBUyxDQUFDLE1BQU0sQ0FBQztZQUN2QixHQUFHLEVBQUUsU0FBUyxDQUFDLEtBQUssQ0FBQztZQUNyQixLQUFLLEVBQUUsU0FBUyxDQUFDLE9BQU8sQ0FBQztTQUMxQixDQUFDO1FBRUYsNkNBQTZDO1FBQzdDLE1BQU0sZUFBZSxHQUFHLE9BQU8sQ0FBQyxJQUFJLEtBQUssTUFBTTtZQUN0QixPQUFPLENBQUMsR0FBRyxLQUFLLE1BQU07WUFDdEIsT0FBTyxDQUFDLEtBQUssS0FBSyxNQUFNLENBQUM7UUFFbEQsTUFBTSxRQUFRLEdBQUcsQ0FBQyxNQUFNLEVBQUUsRUFBRSxDQUFDLENBQUM7WUFDNUIsS0FBSyxFQUFFLE1BQU0sS0FBSyxNQUFNLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLEtBQUssTUFBTSxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQztZQUNsRixRQUFRLEVBQUUsTUFBTTtZQUNoQixXQUFXLEVBQUUsTUFBTTtZQUNuQixVQUFVLEVBQUUsS0FBSztZQUNqQixPQUFPLEVBQUUsYUFBYTtZQUN0QixVQUFVLEVBQUUsUUFBUTtZQUNwQixPQUFPLEVBQUUsU0FBUztZQUNsQixZQUFZLEVBQUUsS0FBSztZQUNuQixlQUFlLEVBQUUsa0JBQWtCO1NBQ3BDLENBQUMsQ0FBQztRQUVILE9BQU8sQ0FDTCxrREFBSyxLQUFLLEVBQUUsRUFBRSxTQUFTLEVBQUUsS0FBSyxFQUFFLFlBQVksRUFBRSxLQUFLLEVBQUUsT0FBTyxFQUFFLE1BQU0sRUFBRSxVQUFVLEVBQUUsUUFBUSxFQUFFO1lBR3pGLGVBQWUsSUFBSSxDQUNsQixrREFBSyxLQUFLLEVBQUU7b0JBQ1YsS0FBSyxFQUFFLFNBQVM7b0JBQ2hCLFdBQVcsRUFBRSxNQUFNO29CQUNuQixZQUFZLEVBQUUsTUFBTTtvQkFDcEIsV0FBVyxFQUFFLGdCQUFnQjtvQkFDN0IsT0FBTyxFQUFFLE1BQU07b0JBQ2YsVUFBVSxFQUFFLFFBQVE7b0JBQ3BCLFVBQVUsRUFBRSxNQUFNO29CQUNsQixRQUFRLEVBQUUsTUFBTTtpQkFDakI7Z0JBQ0MsZ0RBQUcsU0FBUyxFQUFDLGNBQWMsRUFBQyxLQUFLLEVBQUUsRUFBRSxXQUFXLEVBQUUsS0FBSyxFQUFFLEdBQU07a0NBRTNELENBQ1A7WUFHQSxDQUFDLE1BQU0sRUFBRSxLQUFLLEVBQUUsT0FBTyxDQUFDLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsQ0FDbkMsbURBQU0sR0FBRyxFQUFFLEdBQUcsRUFBRSxLQUFLLEVBQUUsUUFBUSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEtBQUssRUFBRSxnQkFBZ0IsT0FBTyxDQUFDLEdBQUcsQ0FBQyxFQUFFO2dCQUNsRixnREFBRyxTQUFTLEVBQUUsTUFBTSxPQUFPLENBQUMsR0FBRyxDQUFDLEtBQUssTUFBTSxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLGVBQWUsRUFBRSxFQUN4RSxLQUFLLEVBQUUsRUFBQyxXQUFXLEVBQUUsS0FBSyxFQUFDLEdBQU07Z0JBQ25DLEdBQUcsQ0FBQyxXQUFXLEVBQUUsQ0FDYixDQUNSLENBQUMsQ0FDRSxDQUNQLENBQUM7SUFDSixDQUFDO0NBQ0Y7QUFsRUQsbUNBa0VDO0FBRUQsMkRBQTJEO0FBQzNELGdCQUFnQixDQUFDLFdBQVcsR0FBRyxrQkFBa0IsQ0FBQztBQUVsRCxrQkFBZSxnQkFBZ0IsQ0FBQyJ9