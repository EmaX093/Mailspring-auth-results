"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mailspring_exports_1 = require("mailspring-exports");
class AuthStatusBridge extends mailspring_exports_1.React.Component {
    constructor(props) {
        super(props);
        this.state = { headers: null, loading: false };
    }
    componentDidMount() {
        this._fetchHeaders();
    }
    componentDidUpdate(prevProps) {
        if (prevProps.message.id !== this.props.message.id) {
            this.setState({ headers: null }, () => this._fetchHeaders());
        }
    }
    async _fetchHeaders() {
        const message = this.props.message;
        if (!message || this.state.loading)
            return;
        this.setState({ loading: true });
        try {
            const path = require('path');
            const fs = require('fs');
            const os = require('os');
            const filepath = path.join(os.tmpdir(), "auth_" + message.id + ".eml");
            const task = new mailspring_exports_1.GetMessageRFC2822Task({
                messageId: message.id,
                accountId: message.accountId,
                filepath: filepath
            });
            mailspring_exports_1.Actions.queueTask(task);
            await mailspring_exports_1.TaskQueue.waitForPerformRemote(task);
            const source = fs.readFileSync(filepath, 'utf8');
            const normalized = source.replace(/\r?\n[ \t]+/g, ' ');
            const headers = {};
            normalized.split(/\r?\n/).forEach(function (line) {
                const parts = line.split(':');
                if (parts.length < 2)
                    return;
                const key = parts.shift().trim();
                const value = parts.join(':').trim();
                if (!headers[key])
                    headers[key] = [];
                headers[key].push(value);
            });
            this.setState({ headers: headers, loading: false });
        }
        catch (err) {
            console.error("Auth Plugin Error:", err);
            this.setState({ loading: false });
        }
    }
    _extractDomain(text) {
        if (!text)
            return null;
        const m = text.match(/@([a-z0-9.-]+)/i);
        if (!m)
            return null;
        return m[1].toLowerCase();
    }
    _parseAuthBlock(text) {
        if (!text)
            return {};
        const getLast = function (regex) {
            const matches = [];
            let m;
            while ((m = regex.exec(text)) !== null) {
                matches.push(m[1].toLowerCase());
            }
            return matches.length ? matches[matches.length - 1] : 'none';
        };
        const dkimDomainMatch = text.match(/header\.d=([a-z0-9.-]+)/i);
        const policyMatch = text.match(/policy\.dmarc=([a-z]+)/i);
        return {
            dkim: getLast(/(?:^|[\s;])dkim=([a-z0-9_-]+)/gi),
            spf: getLast(/(?:^|[\s;])spf=([a-z0-9_-]+)/gi),
            dmarc: getLast(/(?:^|[\s;])dmarc=([a-z0-9_-]+)/gi),
            dkimDomain: dkimDomainMatch ? dkimDomainMatch[1].toLowerCase() : null,
            dmarcPolicy: policyMatch ? policyMatch[1].toLowerCase() : 'none'
        };
    }
    _suspiciousTld(domain) {
        if (!domain)
            return false;
        const badTlds = ["ru", "cn", "tk", "top", "gq", "work", "click"];
        const parts = domain.split('.');
        const tld = parts[parts.length - 1];
        return badTlds.indexOf(tld) !== -1;
    }
    _extractFirstIP(headers) {
        const received = headers['Received'] || [];
        for (let i = 0; i < received.length; i++) {
            const m = received[i].match(/\[([0-9.]+)\]/);
            if (m)
                return m[1];
        }
        return null;
    }
    _getBaseDomain(domain) {
        if (!domain)
            return null;
        const parts = domain.split('.');
        if (parts.length <= 2)
            return domain;
        return parts.slice(parts.length - 2).join('.');
    }
    _isLocalMail(fromDomain, returnDomain) {
        if (!fromDomain || !returnDomain)
            return false;
        return (fromDomain === returnDomain || returnDomain.endsWith("." + fromDomain) || fromDomain.endsWith("." + returnDomain));
    }
    _detectInternalSpoof(fromDomain, returnDomain, accountDomain) {
        const baseFrom = this._getBaseDomain(fromDomain);
        const baseReturn = this._getBaseDomain(returnDomain);
        const baseAccount = this._getBaseDomain(accountDomain);
        const claimsInternal = baseFrom === baseAccount;
        const actuallyInternal = baseReturn === baseAccount || (returnDomain && returnDomain.endsWith("." + baseAccount));
        return claimsInternal && !actuallyInternal;
    }
    /*_detectMailInfra(headers) {
        const received = (headers['Received'] || []).join(" ").toLowerCase();
        if (received.indexOf("google.com") !== -1 || received.indexOf("gmail.com") !== -1) return "Google Workspace";
        if (received.indexOf("outlook.com") !== -1 || received.indexOf("protection.outlook.com") !== -1) return "Microsoft 365";
        if (received.indexOf("amazonses.com") !== -1) return "Amazon SES";
        if (received.indexOf("sendgrid.net") !== -1) return "Sendgrid";
        if (received.indexOf("mailgun.org") !== -1) return "Mailgun";
        
        return received;
    }*/
    _commonOrigins(received_header) {
        if (received_header.indexOf("google.com") !== -1 || received_header.indexOf("gmail.com") !== -1)
            return "Google Workspace";
        if (received_header.indexOf("outlook.com") !== -1 || received_header.indexOf("protection.outlook.com") !== -1)
            return "Microsoft 365";
        if (received_header.indexOf("amazonses.com") !== -1)
            return "Amazon SES";
        if (received_header.indexOf("sendgrid.net") !== -1)
            return "Sendgrid";
        if (received_header.indexOf("mailgun.org") !== -1)
            return "Mailgun";
        return received_header;
    }
    _extractMailRoute(headers) {
        const received = headers['Received'] || [];
        if (!received.length) {
            return {
                origin: null,
                via: null,
                ip: null
            };
        }
        let origin = null;
        let ip = null;
        let via = null;
        // último salto hacia tu servidor
        const lastHop = received[0];
        const viaMatch = lastHop.match(/from\s+([a-z0-9.-]+)/i);
        if (viaMatch) {
            via = viaMatch[1].toLowerCase();
        }
        // buscar origen real (último received de la cadena)
        for (let i = received.length - 1; i >= 0; i--) {
            const r = received[i];
            const originMatch = r.match(/helo=([a-z0-9.-]+)/i)
                || r.match(/from\s+([a-z0-9.-]+)/i);
            if (originMatch) {
                origin = originMatch[1].toLowerCase();
            }
            const ipMatch = r.match(/\[([0-9a-f:.]+)\]/i);
            if (ipMatch) {
                ip = ipMatch[1];
            }
            if (origin)
                break;
        }
        return {
            origin: this._commonOrigins(origin),
            via: this._commonOrigins(via),
        };
    }
    render() {
        const headers = this.state.headers;
        if (!headers)
            return null;
        const authBlocks = []
            .concat(headers["Authentication-Results"] || [])
            .concat(headers["ARC-Authentication-Results"] || []);
        const parsed = authBlocks.map(this._parseAuthBlock.bind(this));
        const last = parsed.length ? parsed[parsed.length - 1] : {};
        const res = {
            dkim: parsed.some(function (r) {
                return r.dkim === "pass";
            })
                ? "pass"
                : last.dkim || "none",
            spf: parsed.some(function (r) {
                return r.spf === "pass";
            })
                ? "pass"
                : last.spf || "none",
            dmarc: parsed.some(function (r) {
                return r.dmarc === "pass";
            })
                ? "pass"
                : last.dmarc || "none",
            dkimDomain: last.dkimDomain || null,
        };
        const from = headers["From"] ? headers["From"][0] : "";
        const reply = headers["Reply-To"] ? headers["Reply-To"][0] : "";
        const returnPath = headers["Return-Path"] ? headers["Return-Path"][0] : "";
        const fromDomain = this._extractDomain(from);
        const replyDomain = this._extractDomain(reply);
        const returnDomain = this._extractDomain(returnPath);
        const accountEmail = this.props.account
            ? this.props.account.emailAddress
            : null;
        const accountDomain = this._extractDomain(accountEmail);
        const spoofInternal = this._detectInternalSpoof(fromDomain, returnDomain, accountDomain);
        if (spoofInternal) {
            return (mailspring_exports_1.React.createElement("div", { style: { marginTop: "6px" } },
                " ",
                mailspring_exports_1.React.createElement("span", { style: { color: "#dc3545", fontWeight: "bold" } },
                    " ",
                    "\u26A0 INTERNAL DOMAIN SPOOFING",
                    " "),
                " "));
        }
        const replyMismatch = replyDomain && fromDomain && replyDomain !== fromDomain;
        const returnMismatch = returnDomain && fromDomain && returnDomain !== fromDomain;
        const suspiciousTld = this._suspiciousTld(fromDomain);
        const firstIP = this._extractFirstIP(headers);
        const infra = this._extractMailRoute(headers); // this._detectMailInfra(headers);
        const verified = res.dkim === "pass" && res.spf === "pass" && res.dmarc === "pass";
        const arcSeal = headers['ARC-Seal'] ? headers['ARC-Seal'][0] : '';
        const arcPass = /cv=pass/i.test(arcSeal);
        return (mailspring_exports_1.React.createElement("div", { style: {
                display: "flex",
                flexWrap: "wrap",
                gap: "10px",
                fontSize: "11px",
                marginTop: "6px",
            } },
            " ",
            verified && mailspring_exports_1.React.createElement("span", { style: { color: "#28a745" } }, "\u2714 VERIFIED"),
            " ",
            mailspring_exports_1.React.createElement("span", { style: { color: res.dkim === "pass" ? "#28a745" : "#888" } },
                mailspring_exports_1.React.createElement("i", { className: "fa " + (res['dkim'] === 'pass' ? 'fa-lock' : 'fa-unlock') }),
                " ",
                "DKIM",
                " "),
            " ",
            mailspring_exports_1.React.createElement("span", { style: { color: res.spf === "pass" ? "#28a745" : "#888" } },
                mailspring_exports_1.React.createElement("i", { className: "fa " + (res['spf'] === 'pass' ? 'fa-lock' : 'fa-unlock') }),
                " ",
                "SPF",
                " "),
            " ",
            mailspring_exports_1.React.createElement("span", { style: { color: res.dmarc === "pass" ? "#28a745" : "#888" } },
                " ",
                mailspring_exports_1.React.createElement("i", { className: "fa " + (res['dmarc'] === 'pass' ? 'fa-lock' : 'fa-unlock') }),
                " ",
                "DMARC",
                " "),
            " ",
            arcPass && (mailspring_exports_1.React.createElement("span", { style: { color: '#17a2b8' } },
                mailspring_exports_1.React.createElement("i", { className: 'fa fa-check' }),
                " ARC Sealed",
                " ")),
            " ",
            replyMismatch && (mailspring_exports_1.React.createElement("span", { style: { color: "#dc3545" } }, " \u26A0 REPLY-TO DIFFERENT DOMAIN ")),
            " ",
            returnMismatch && (mailspring_exports_1.React.createElement("span", { style: { color: "#dc3545" } }, " \u26A0 RETURN-PATH DIFFERENT ")),
            " ",
            suspiciousTld && (mailspring_exports_1.React.createElement("span", { style: { color: "#ff8800" } }, " \u26A0 SUSPICIOUS TLD ")),
            " ",
            infra && infra.origin == infra.via && infra.origin && infra.via && mailspring_exports_1.React.createElement("span", { style: { color: "#17a2b8" } },
                mailspring_exports_1.React.createElement("i", { className: "fa fa-map" }),
                " via ",
                infra.origin,
                " "),
            " ",
            infra && infra.origin != infra.via && infra.origin && infra.via && mailspring_exports_1.React.createElement("span", { style: { color: "#17a2b8" } },
                mailspring_exports_1.React.createElement("i", { className: "fa fa-map" }),
                " origin ",
                infra.origin,
                " via ",
                infra.via,
                " "),
            " ",
            firstIP && mailspring_exports_1.React.createElement("span", { style: { color: "#888" } },
                " IP ",
                firstIP,
                " "),
            " "));
    }
}
AuthStatusBridge.displayName = 'AuthStatusBridge';
exports.default = AuthStatusBridge;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC1zdGF0dXMtYnJpZGdlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2F1dGgtc3RhdHVzLWJyaWRnZS5qc3giXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSwyREFBc0Y7QUFFdEYsTUFBTSxnQkFBaUIsU0FBUSwwQkFBSyxDQUFDLFNBQVM7SUFJNUMsWUFBWSxLQUFLO1FBQ2YsS0FBSyxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ2IsSUFBSSxDQUFDLEtBQUssR0FBRyxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLEtBQUssRUFBRSxDQUFDO0lBQ2pELENBQUM7SUFFRCxpQkFBaUI7UUFDZixJQUFJLENBQUMsYUFBYSxFQUFFLENBQUM7SUFDdkIsQ0FBQztJQUVELGtCQUFrQixDQUFDLFNBQVM7UUFDMUIsSUFBSSxTQUFTLENBQUMsT0FBTyxDQUFDLEVBQUUsS0FBSyxJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxFQUFFLEVBQUU7WUFDbEQsSUFBSSxDQUFDLFFBQVEsQ0FBQyxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsRUFBRSxHQUFHLEVBQUUsQ0FBQyxJQUFJLENBQUMsYUFBYSxFQUFFLENBQUMsQ0FBQztTQUM5RDtJQUNILENBQUM7SUFFRCxLQUFLLENBQUMsYUFBYTtRQUVqQixNQUFNLE9BQU8sR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQztRQUNuQyxJQUFJLENBQUMsT0FBTyxJQUFJLElBQUksQ0FBQyxLQUFLLENBQUMsT0FBTztZQUFFLE9BQU87UUFFM0MsSUFBSSxDQUFDLFFBQVEsQ0FBQyxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO1FBRWpDLElBQUk7WUFFRixNQUFNLElBQUksR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7WUFDN0IsTUFBTSxFQUFFLEdBQUcsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDO1lBQ3pCLE1BQU0sRUFBRSxHQUFHLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQztZQUV6QixNQUFNLFFBQVEsR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxNQUFNLEVBQUUsRUFBRSxPQUFPLEdBQUcsT0FBTyxDQUFDLEVBQUUsR0FBRyxNQUFNLENBQUMsQ0FBQztZQUV2RSxNQUFNLElBQUksR0FBRyxJQUFJLDBDQUFxQixDQUFDO2dCQUNyQyxTQUFTLEVBQUUsT0FBTyxDQUFDLEVBQUU7Z0JBQ3JCLFNBQVMsRUFBRSxPQUFPLENBQUMsU0FBUztnQkFDNUIsUUFBUSxFQUFFLFFBQVE7YUFDbkIsQ0FBQyxDQUFDO1lBRUgsNEJBQU8sQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLENBQUM7WUFDeEIsTUFBTSw4QkFBUyxDQUFDLG9CQUFvQixDQUFDLElBQUksQ0FBQyxDQUFDO1lBRTNDLE1BQU0sTUFBTSxHQUFHLEVBQUUsQ0FBQyxZQUFZLENBQUMsUUFBUSxFQUFFLE1BQU0sQ0FBQyxDQUFDO1lBRWpELE1BQU0sVUFBVSxHQUFHLE1BQU0sQ0FBQyxPQUFPLENBQUMsY0FBYyxFQUFFLEdBQUcsQ0FBQyxDQUFDO1lBRXZELE1BQU0sT0FBTyxHQUFHLEVBQUUsQ0FBQztZQUVuQixVQUFVLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxDQUFDLE9BQU8sQ0FBQyxVQUFTLElBQUk7Z0JBRTdDLE1BQU0sS0FBSyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBQzlCLElBQUksS0FBSyxDQUFDLE1BQU0sR0FBRyxDQUFDO29CQUFFLE9BQU87Z0JBRTdCLE1BQU0sR0FBRyxHQUFHLEtBQUssQ0FBQyxLQUFLLEVBQUUsQ0FBQyxJQUFJLEVBQUUsQ0FBQztnQkFDakMsTUFBTSxLQUFLLEdBQUcsS0FBSyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLEVBQUUsQ0FBQztnQkFFckMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUM7b0JBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVBQUUsQ0FBQztnQkFDckMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUUzQixDQUFDLENBQUMsQ0FBQztZQUVILElBQUksQ0FBQyxRQUFRLENBQUMsRUFBRSxPQUFPLEVBQUUsT0FBTyxFQUFFLE9BQU8sRUFBRSxLQUFLLEVBQUUsQ0FBQyxDQUFDO1NBRXJEO1FBQUMsT0FBTyxHQUFHLEVBQUU7WUFFWixPQUFPLENBQUMsS0FBSyxDQUFDLG9CQUFvQixFQUFFLEdBQUcsQ0FBQyxDQUFDO1lBQ3pDLElBQUksQ0FBQyxRQUFRLENBQUMsRUFBRSxPQUFPLEVBQUUsS0FBSyxFQUFFLENBQUMsQ0FBQztTQUVuQztJQUNILENBQUM7SUFFRCxjQUFjLENBQUMsSUFBSTtRQUVqQixJQUFJLENBQUMsSUFBSTtZQUFFLE9BQU8sSUFBSSxDQUFDO1FBRXZCLE1BQU0sQ0FBQyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsaUJBQWlCLENBQUMsQ0FBQztRQUN4QyxJQUFJLENBQUMsQ0FBQztZQUFFLE9BQU8sSUFBSSxDQUFDO1FBRXBCLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDO0lBRTVCLENBQUM7SUFFRCxlQUFlLENBQUMsSUFBSTtRQUVsQixJQUFJLENBQUMsSUFBSTtZQUFFLE9BQU8sRUFBRSxDQUFDO1FBRXJCLE1BQU0sT0FBTyxHQUFHLFVBQVMsS0FBSztZQUU1QixNQUFNLE9BQU8sR0FBRyxFQUFFLENBQUM7WUFDbkIsSUFBSSxDQUFDLENBQUM7WUFFTixPQUFPLENBQUMsQ0FBQyxHQUFHLEtBQUssQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsS0FBSyxJQUFJLEVBQUU7Z0JBQ3RDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDLENBQUM7YUFDbEM7WUFFRCxPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUM7UUFDL0QsQ0FBQyxDQUFDO1FBRUYsTUFBTSxlQUFlLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQywwQkFBMEIsQ0FBQyxDQUFDO1FBQy9ELE1BQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMseUJBQXlCLENBQUMsQ0FBQztRQUUxRCxPQUFPO1lBRUwsSUFBSSxFQUFFLE9BQU8sQ0FBQyxpQ0FBaUMsQ0FBQztZQUNoRCxHQUFHLEVBQUUsT0FBTyxDQUFDLGdDQUFnQyxDQUFDO1lBQzlDLEtBQUssRUFBRSxPQUFPLENBQUMsa0NBQWtDLENBQUM7WUFFbEQsVUFBVSxFQUFFLGVBQWUsQ0FBQyxDQUFDLENBQUMsZUFBZSxDQUFDLENBQUMsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJO1lBQ3JFLFdBQVcsRUFBRSxXQUFXLENBQUMsQ0FBQyxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxDQUFDLENBQUMsTUFBTTtTQUVqRSxDQUFDO0lBRUosQ0FBQztJQUVELGNBQWMsQ0FBQyxNQUFNO1FBRW5CLElBQUksQ0FBQyxNQUFNO1lBQUUsT0FBTyxLQUFLLENBQUM7UUFFMUIsTUFBTSxPQUFPLEdBQUcsQ0FBQyxJQUFJLEVBQUMsSUFBSSxFQUFDLElBQUksRUFBQyxLQUFLLEVBQUMsSUFBSSxFQUFDLE1BQU0sRUFBQyxPQUFPLENBQUMsQ0FBQztRQUUzRCxNQUFNLEtBQUssR0FBRyxNQUFNLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQ2hDLE1BQU0sR0FBRyxHQUFHLEtBQUssQ0FBQyxLQUFLLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFDO1FBRXBDLE9BQU8sT0FBTyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQztJQUVyQyxDQUFDO0lBRUQsZUFBZSxDQUFDLE9BQU87UUFFckIsTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFVBQVUsQ0FBQyxJQUFJLEVBQUUsQ0FBQztRQUUzQyxLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsUUFBUSxDQUFDLE1BQU0sRUFBRSxDQUFDLEVBQUUsRUFBRTtZQUV4QyxNQUFNLENBQUMsR0FBRyxRQUFRLENBQUMsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLGVBQWUsQ0FBQyxDQUFDO1lBRTdDLElBQUksQ0FBQztnQkFBRSxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztTQUVwQjtRQUVELE9BQU8sSUFBSSxDQUFDO0lBRWQsQ0FBQztJQUVGLGNBQWMsQ0FBQyxNQUFNO1FBQ3BCLElBQUksQ0FBQyxNQUFNO1lBQUUsT0FBTyxJQUFJLENBQUM7UUFDekIsTUFBTSxLQUFLLEdBQUcsTUFBTSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQztRQUNoQyxJQUFJLEtBQUssQ0FBQyxNQUFNLElBQUksQ0FBQztZQUFFLE9BQU8sTUFBTSxDQUFDO1FBQ3JDLE9BQU8sS0FBSyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUNoRCxDQUFDO0lBQ0QsWUFBWSxDQUFDLFVBQVUsRUFBRSxZQUFZO1FBQ3BDLElBQUksQ0FBQyxVQUFVLElBQUksQ0FBQyxZQUFZO1lBQUUsT0FBTyxLQUFLLENBQUM7UUFDL0MsT0FBTyxDQUFDLFVBQVUsS0FBSyxZQUFZLElBQUksWUFBWSxDQUFDLFFBQVEsQ0FBQyxHQUFHLEdBQUcsVUFBVSxDQUFDLElBQUksVUFBVSxDQUFDLFFBQVEsQ0FBQyxHQUFHLEdBQUcsWUFBWSxDQUFDLENBQUMsQ0FBQztJQUM1SCxDQUFDO0lBRUQsb0JBQW9CLENBQUMsVUFBVSxFQUFFLFlBQVksRUFBRSxhQUFhO1FBQzNELE1BQU0sUUFBUSxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUMsVUFBVSxDQUFDLENBQUM7UUFDakQsTUFBTSxVQUFVLEdBQUcsSUFBSSxDQUFDLGNBQWMsQ0FBQyxZQUFZLENBQUMsQ0FBQztRQUNyRCxNQUFNLFdBQVcsR0FBRyxJQUFJLENBQUMsY0FBYyxDQUFDLGFBQWEsQ0FBQyxDQUFDO1FBQ3ZELE1BQU0sY0FBYyxHQUFHLFFBQVEsS0FBSyxXQUFXLENBQUM7UUFDaEQsTUFBTSxnQkFBZ0IsR0FBRyxVQUFVLEtBQUssV0FBVyxJQUFJLENBQUMsWUFBWSxJQUFJLFlBQVksQ0FBQyxRQUFRLENBQUMsR0FBRyxHQUFHLFdBQVcsQ0FBQyxDQUFDLENBQUM7UUFDbEgsT0FBTyxjQUFjLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQztJQUM1QyxDQUFDO0lBRUQ7Ozs7Ozs7OztPQVNHO0lBRUgsY0FBYyxDQUFDLGVBQWU7UUFDN0IsSUFBSSxlQUFlLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxLQUFLLENBQUMsQ0FBQyxJQUFJLGVBQWUsQ0FBQyxPQUFPLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQUUsT0FBTyxrQkFBa0IsQ0FBQztRQUMzSCxJQUFJLGVBQWUsQ0FBQyxPQUFPLENBQUMsYUFBYSxDQUFDLEtBQUssQ0FBQyxDQUFDLElBQUksZUFBZSxDQUFDLE9BQU8sQ0FBQyx3QkFBd0IsQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUFFLE9BQU8sZUFBZSxDQUFDO1FBQ3RJLElBQUksZUFBZSxDQUFDLE9BQU8sQ0FBQyxlQUFlLENBQUMsS0FBSyxDQUFDLENBQUM7WUFBRSxPQUFPLFlBQVksQ0FBQztRQUN6RSxJQUFJLGVBQWUsQ0FBQyxPQUFPLENBQUMsY0FBYyxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQUUsT0FBTyxVQUFVLENBQUM7UUFDdEUsSUFBSSxlQUFlLENBQUMsT0FBTyxDQUFDLGFBQWEsQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUFFLE9BQU8sU0FBUyxDQUFDO1FBRXBFLE9BQU8sZUFBZSxDQUFDO0lBQ3hCLENBQUM7SUFFRCxpQkFBaUIsQ0FBQyxPQUFPO1FBRXRCLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxVQUFVLENBQUMsSUFBSSxFQUFFLENBQUM7UUFFM0MsSUFBRyxDQUFDLFFBQVEsQ0FBQyxNQUFNLEVBQUM7WUFDckIsT0FBTztnQkFDTCxNQUFNLEVBQUMsSUFBSTtnQkFDWCxHQUFHLEVBQUMsSUFBSTtnQkFDUixFQUFFLEVBQUMsSUFBSTthQUNSLENBQUM7U0FDQTtRQUVELElBQUksTUFBTSxHQUFDLElBQUksQ0FBQztRQUNoQixJQUFJLEVBQUUsR0FBQyxJQUFJLENBQUM7UUFDWixJQUFJLEdBQUcsR0FBQyxJQUFJLENBQUM7UUFFYixpQ0FBaUM7UUFDakMsTUFBTSxPQUFPLEdBQUcsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBRTVCLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxLQUFLLENBQUMsdUJBQXVCLENBQUMsQ0FBQztRQUN4RCxJQUFHLFFBQVEsRUFBQztZQUNiLEdBQUcsR0FBRyxRQUFRLENBQUMsQ0FBQyxDQUFDLENBQUMsV0FBVyxFQUFFLENBQUM7U0FDOUI7UUFFRCxvREFBb0Q7UUFDcEQsS0FBSSxJQUFJLENBQUMsR0FBRyxRQUFRLENBQUMsTUFBTSxHQUFDLENBQUMsRUFBRSxDQUFDLElBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFDO1lBRTFDLE1BQU0sQ0FBQyxHQUFHLFFBQVEsQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUV0QixNQUFNLFdBQVcsR0FBRyxDQUFDLENBQUMsS0FBSyxDQUFDLHFCQUFxQixDQUFDO21CQUM3QyxDQUFDLENBQUMsS0FBSyxDQUFDLHVCQUF1QixDQUFDLENBQUM7WUFFdEMsSUFBRyxXQUFXLEVBQUM7Z0JBQ2IsTUFBTSxHQUFHLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQzthQUN2QztZQUVELE1BQU0sT0FBTyxHQUFHLENBQUMsQ0FBQyxLQUFLLENBQUMsb0JBQW9CLENBQUMsQ0FBQztZQUM5QyxJQUFHLE9BQU8sRUFBQztnQkFDVCxFQUFFLEdBQUcsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDO2FBQ2pCO1lBRUQsSUFBRyxNQUFNO2dCQUFFLE1BQU07U0FFZjtRQUVELE9BQU87WUFDUixNQUFNLEVBQUUsSUFBSSxDQUFDLGNBQWMsQ0FBQyxNQUFNLENBQUM7WUFDbkMsR0FBRyxFQUFFLElBQUksQ0FBQyxjQUFjLENBQUMsR0FBRyxDQUFDO1NBRTNCLENBQUM7SUFFSixDQUFDO0lBRUQsTUFBTTtRQUVSLE1BQU0sT0FBTyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDO1FBQ25DLElBQUksQ0FBQyxPQUFPO1lBQUUsT0FBTyxJQUFJLENBQUM7UUFDMUIsTUFBTSxVQUFVLEdBQUcsRUFBRTthQUNsQixNQUFNLENBQUMsT0FBTyxDQUFDLHdCQUF3QixDQUFDLElBQUksRUFBRSxDQUFDO2FBQy9DLE1BQU0sQ0FBQyxPQUFPLENBQUMsNEJBQTRCLENBQUMsSUFBSSxFQUFFLENBQUMsQ0FBQztRQUN2RCxNQUFNLE1BQU0sR0FBRyxVQUFVLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxlQUFlLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUM7UUFDL0QsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQztRQUM1RCxNQUFNLEdBQUcsR0FBRztZQUNWLElBQUksRUFBRSxNQUFNLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQztnQkFDM0IsT0FBTyxDQUFDLENBQUMsSUFBSSxLQUFLLE1BQU0sQ0FBQztZQUMzQixDQUFDLENBQUM7Z0JBQ0EsQ0FBQyxDQUFDLE1BQU07Z0JBQ1IsQ0FBQyxDQUFDLElBQUksQ0FBQyxJQUFJLElBQUksTUFBTTtZQUN2QixHQUFHLEVBQUUsTUFBTSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUM7Z0JBQzFCLE9BQU8sQ0FBQyxDQUFDLEdBQUcsS0FBSyxNQUFNLENBQUM7WUFDMUIsQ0FBQyxDQUFDO2dCQUNBLENBQUMsQ0FBQyxNQUFNO2dCQUNSLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxJQUFJLE1BQU07WUFDdEIsS0FBSyxFQUFFLE1BQU0sQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDO2dCQUM1QixPQUFPLENBQUMsQ0FBQyxLQUFLLEtBQUssTUFBTSxDQUFDO1lBQzVCLENBQUMsQ0FBQztnQkFDQSxDQUFDLENBQUMsTUFBTTtnQkFDUixDQUFDLENBQUMsSUFBSSxDQUFDLEtBQUssSUFBSSxNQUFNO1lBQ3hCLFVBQVUsRUFBRSxJQUFJLENBQUMsVUFBVSxJQUFJLElBQUk7U0FDcEMsQ0FBQztRQUNGLE1BQU0sSUFBSSxHQUFHLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUM7UUFDdkQsTUFBTSxLQUFLLEdBQUcsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQztRQUNoRSxNQUFNLFVBQVUsR0FBRyxPQUFPLENBQUMsYUFBYSxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDO1FBQzNFLE1BQU0sVUFBVSxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUMsSUFBSSxDQUFDLENBQUM7UUFDN0MsTUFBTSxXQUFXLEdBQUcsSUFBSSxDQUFDLGNBQWMsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUMvQyxNQUFNLFlBQVksR0FBRyxJQUFJLENBQUMsY0FBYyxDQUFDLFVBQVUsQ0FBQyxDQUFDO1FBQ3JELE1BQU0sWUFBWSxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsT0FBTztZQUNyQyxDQUFDLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsWUFBWTtZQUNqQyxDQUFDLENBQUMsSUFBSSxDQUFDO1FBQ1QsTUFBTSxhQUFhLEdBQUcsSUFBSSxDQUFDLGNBQWMsQ0FBQyxZQUFZLENBQUMsQ0FBQztRQUN4RCxNQUFNLGFBQWEsR0FBRyxJQUFJLENBQUMsb0JBQW9CLENBQzdDLFVBQVUsRUFDVixZQUFZLEVBQ1osYUFBYSxDQUNkLENBQUM7UUFDRixJQUFJLGFBQWEsRUFBRTtZQUNqQixPQUFPLENBQ0wsa0RBQUssS0FBSyxFQUFFLEVBQUUsU0FBUyxFQUFFLEtBQUssRUFBRTtnQkFDN0IsR0FBRztnQkFDSixtREFBTSxLQUFLLEVBQUUsRUFBRSxLQUFLLEVBQUUsU0FBUyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUU7b0JBQ2xELEdBQUc7O29CQUN1QixHQUFHLENBQ3pCO2dCQUFDLEdBQUcsQ0FDUCxDQUNQLENBQUM7U0FDSDtRQUVELE1BQU0sYUFBYSxHQUFHLFdBQVcsSUFBSSxVQUFVLElBQUksV0FBVyxLQUFLLFVBQVUsQ0FBQztRQUM5RSxNQUFNLGNBQWMsR0FDbEIsWUFBWSxJQUFJLFVBQVUsSUFBSSxZQUFZLEtBQUssVUFBVSxDQUFDO1FBQzVELE1BQU0sYUFBYSxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUMsVUFBVSxDQUFDLENBQUM7UUFDdEQsTUFBTSxPQUFPLEdBQUcsSUFBSSxDQUFDLGVBQWUsQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUM5QyxNQUFNLEtBQUssR0FBRyxJQUFJLENBQUMsaUJBQWlCLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxrQ0FBa0M7UUFDakYsTUFBTSxRQUFRLEdBQ1osR0FBRyxDQUFDLElBQUksS0FBSyxNQUFNLElBQUksR0FBRyxDQUFDLEdBQUcsS0FBSyxNQUFNLElBQUksR0FBRyxDQUFDLEtBQUssS0FBSyxNQUFNLENBQUM7UUFDcEUsTUFBTSxPQUFPLEdBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQztRQUNoRSxNQUFNLE9BQU8sR0FBQyxVQUFVLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBR3ZDLE9BQU8sQ0FDTCxrREFDRSxLQUFLLEVBQUU7Z0JBQ0wsT0FBTyxFQUFFLE1BQU07Z0JBQ2YsUUFBUSxFQUFFLE1BQU07Z0JBQ2hCLEdBQUcsRUFBRSxNQUFNO2dCQUNYLFFBQVEsRUFBRSxNQUFNO2dCQUNoQixTQUFTLEVBQUUsS0FBSzthQUNqQjtZQUVBLEdBQUc7WUFDSCxRQUFRLElBQUksbURBQU0sS0FBSyxFQUFFLEVBQUUsS0FBSyxFQUFFLFNBQVMsRUFBRSxzQkFBbUI7WUFBRSxHQUFHO1lBQ3RFLG1EQUFNLEtBQUssRUFBRSxFQUFFLEtBQUssRUFBRSxHQUFHLENBQUMsSUFBSSxLQUFLLE1BQU0sQ0FBQyxDQUFDLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQyxNQUFNLEVBQUU7Z0JBQ2pFLGdEQUFHLFNBQVMsRUFBRSxLQUFLLEdBQUcsQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLEtBQUcsTUFBTSxDQUFBLENBQUMsQ0FBQSxTQUFTLENBQUEsQ0FBQyxDQUFBLFdBQVcsQ0FBQyxHQUFNO2dCQUFDLEdBQUc7O2dCQUNwRSxHQUFHLENBQ0g7WUFBQyxHQUFHO1lBQ1gsbURBQU0sS0FBSyxFQUFFLEVBQUUsS0FBSyxFQUFFLEdBQUcsQ0FBQyxHQUFHLEtBQUssTUFBTSxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLE1BQU0sRUFBRTtnQkFDaEUsZ0RBQUcsU0FBUyxFQUFFLEtBQUssR0FBRyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsS0FBRyxNQUFNLENBQUEsQ0FBQyxDQUFBLFNBQVMsQ0FBQSxDQUFDLENBQUEsV0FBVyxDQUFDLEdBQU07Z0JBQUMsR0FBRzs7Z0JBQ3BFLEdBQUcsQ0FDRjtZQUFDLEdBQUc7WUFDWCxtREFBTSxLQUFLLEVBQUUsRUFBRSxLQUFLLEVBQUUsR0FBRyxDQUFDLEtBQUssS0FBSyxNQUFNLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsTUFBTSxFQUFFO2dCQUFHLEdBQUc7Z0JBQ3hFLGdEQUFHLFNBQVMsRUFBRSxLQUFLLEdBQUcsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLEtBQUcsTUFBTSxDQUFBLENBQUMsQ0FBQSxTQUFTLENBQUEsQ0FBQyxDQUFBLFdBQVcsQ0FBQyxHQUFNO2dCQUFDLEdBQUc7O2dCQUNwRSxHQUFHLENBQ0o7WUFBQyxHQUFHO1lBQ2IsT0FBTyxJQUFJLENBQ1osbURBQU0sS0FBSyxFQUFFLEVBQUMsS0FBSyxFQUFDLFNBQVMsRUFBQztnQkFDN0IsZ0RBQUcsU0FBUyxFQUFDLGFBQWEsR0FBSzs7Z0JBQVksR0FBRyxDQUN4QyxDQUNOO1lBQUUsR0FBRztZQUNGLGFBQWEsSUFBSSxDQUNoQixtREFBTSxLQUFLLEVBQUUsRUFBRSxLQUFLLEVBQUUsU0FBUyxFQUFFLHlDQUFzQyxDQUN4RTtZQUFFLEdBQUc7WUFDTCxjQUFjLElBQUksQ0FDakIsbURBQU0sS0FBSyxFQUFFLEVBQUUsS0FBSyxFQUFFLFNBQVMsRUFBRSxxQ0FBa0MsQ0FDcEU7WUFBRSxHQUFHO1lBQ0wsYUFBYSxJQUFJLENBQ2hCLG1EQUFNLEtBQUssRUFBRSxFQUFFLEtBQUssRUFBRSxTQUFTLEVBQUUsOEJBQTJCLENBQzdEO1lBQUUsR0FBRztZQUNMLEtBQUssSUFBSSxLQUFLLENBQUMsTUFBTSxJQUFJLEtBQUssQ0FBQyxHQUFHLElBQUksS0FBSyxDQUFDLE1BQU0sSUFBSSxLQUFLLENBQUMsR0FBRyxJQUFJLG1EQUFNLEtBQUssRUFBRSxFQUFFLEtBQUssRUFBRSxTQUFTLEVBQUU7Z0JBQUUsZ0RBQUcsU0FBUyxFQUFDLFdBQVcsR0FBSzs7Z0JBQU0sS0FBSyxDQUFDLE1BQU07b0JBQVM7WUFBRSxHQUFHO1lBQ3RLLEtBQUssSUFBSSxLQUFLLENBQUMsTUFBTSxJQUFJLEtBQUssQ0FBQyxHQUFHLElBQUksS0FBSyxDQUFDLE1BQU0sSUFBSSxLQUFLLENBQUMsR0FBRyxJQUFJLG1EQUFNLEtBQUssRUFBRSxFQUFFLEtBQUssRUFBRSxTQUFTLEVBQUU7Z0JBQUUsZ0RBQUcsU0FBUyxFQUFDLFdBQVcsR0FBSzs7Z0JBQVMsS0FBSyxDQUFDLE1BQU07O2dCQUFPLEtBQUssQ0FBQyxHQUFHO29CQUFTO1lBQUUsR0FBRztZQUVuTCxPQUFPLElBQUksbURBQU0sS0FBSyxFQUFFLEVBQUUsS0FBSyxFQUFFLE1BQU0sRUFBRTs7Z0JBQU8sT0FBTztvQkFBUztZQUFFLEdBQUcsQ0FDbEUsQ0FDUCxDQUFDO0lBRUEsQ0FBQzs7QUEzVk0sNEJBQVcsR0FBRyxrQkFBa0IsQ0FBQztBQStWMUMsa0JBQWUsZ0JBQWdCLENBQUMifQ==