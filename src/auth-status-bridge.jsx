import { React, Actions, TaskQueue, GetMessageRFC2822Task } from 'mailspring-exports';

class AuthStatusBridge extends React.Component {

  static displayName = 'AuthStatusBridge';

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
    if (!message || this.state.loading) return;

    this.setState({ loading: true });

    try {

      const path = require('path');
      const fs = require('fs');
      const os = require('os');

      const filepath = path.join(os.tmpdir(), "auth_" + message.id + ".eml");

      const task = new GetMessageRFC2822Task({
        messageId: message.id,
        accountId: message.accountId,
        filepath: filepath
      });

      Actions.queueTask(task);
      await TaskQueue.waitForPerformRemote(task);

      const source = fs.readFileSync(filepath, 'utf8');

      const normalized = source.replace(/\r?\n[ \t]+/g, ' ');

      const headers = {};

      normalized.split(/\r?\n/).forEach(function(line) {

        const parts = line.split(':');
        if (parts.length < 2) return;

        const key = parts.shift().trim();
        const value = parts.join(':').trim();

        if (!headers[key]) headers[key] = [];
        headers[key].push(value);

      });

      this.setState({ headers: headers, loading: false });

    } catch (err) {

      console.error("Auth Plugin Error:", err);
      this.setState({ loading: false });

    }
  }

  _extractDomain(text) {

    if (!text) return null;

    const m = text.match(/@([a-z0-9.-]+)/i);
    if (!m) return null;

    return m[1].toLowerCase();

  }

  _parseAuthBlock(text) {

    if (!text) return {};

    const getLast = function(regex) {

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

    if (!domain) return false;

    const badTlds = ["ru","cn","tk","top","gq","work","click"];

    const parts = domain.split('.');
    const tld = parts[parts.length - 1];

    return badTlds.indexOf(tld) !== -1;

  }

  _extractFirstIP(headers) {

    const received = headers['Received'] || [];

    for (let i = 0; i < received.length; i++) {

      const m = received[i].match(/\[([0-9.]+)\]/);

      if (m) return m[1];

    }

    return null;

  }
  
	_getBaseDomain(domain) {
		if (!domain) return null;
		const parts = domain.split('.');
		if (parts.length <= 2) return domain;
		return parts.slice(parts.length - 2).join('.');
	}
	_isLocalMail(fromDomain, returnDomain) {
		if (!fromDomain || !returnDomain) return false;
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
		if (received_header.indexOf("google.com") !== -1 || received_header.indexOf("gmail.com") !== -1) return "Google Workspace";
		if (received_header.indexOf("outlook.com") !== -1 || received_header.indexOf("protection.outlook.com") !== -1) return "Microsoft 365";
		if (received_header.indexOf("amazonses.com") !== -1) return "Amazon SES";
		if (received_header.indexOf("sendgrid.net") !== -1) return "Sendgrid";
		if (received_header.indexOf("mailgun.org") !== -1) return "Mailgun";

		return received_header;
	}
	
	_extractMailRoute(headers){

		  const received = headers['Received'] || [];

		  if(!received.length){
			return {
			  origin:null,
			  via:null,
			  ip:null
			};
		  }

		  let origin=null;
		  let ip=null;
		  let via=null;

		  // último salto hacia tu servidor
		  const lastHop = received[0];

		  const viaMatch = lastHop.match(/from\s+([a-z0-9.-]+)/i);
		  if(viaMatch){
			via = viaMatch[1].toLowerCase();
		  }

		  // buscar origen real (último received de la cadena)
		  for(let i = received.length-1; i>=0; i--){

			const r = received[i];

			const originMatch = r.match(/helo=([a-z0-9.-]+)/i)
			  || r.match(/from\s+([a-z0-9.-]+)/i);

			if(originMatch){
			  origin = originMatch[1].toLowerCase();
			}

			const ipMatch = r.match(/\[([0-9a-f:.]+)\]/i);
			if(ipMatch){
			  ip = ipMatch[1];
			}

			if(origin) break;

		  }

		  return {
			origin: this._commonOrigins(origin),
			via: this._commonOrigins(via),
			//ip: ip
		  };

		}

  render() {

const headers = this.state.headers;
if (!headers) return null;
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
const spoofInternal = this._detectInternalSpoof(
  fromDomain,
  returnDomain,
  accountDomain
);
if (spoofInternal) {
  return (
    <div style={{ marginTop: "6px" }}>
      {" "}
      <span style={{ color: "#dc3545", fontWeight: "bold" }}>
        {" "}
        ⚠ INTERNAL DOMAIN SPOOFING{" "}
      </span>{" "}
    </div>
  );
}

const replyMismatch = replyDomain && fromDomain && replyDomain !== fromDomain;
const returnMismatch =
  returnDomain && fromDomain && returnDomain !== fromDomain;
const suspiciousTld = this._suspiciousTld(fromDomain);
const firstIP = this._extractFirstIP(headers);
const infra = this._extractMailRoute(headers); // this._detectMailInfra(headers);
const verified =
  res.dkim === "pass" && res.spf === "pass" && res.dmarc === "pass";
const arcSeal=headers['ARC-Seal'] ? headers['ARC-Seal'][0] : '';
const arcPass=/cv=pass/i.test(arcSeal);


return (
  <div
    style={{
      display: "flex",
      flexWrap: "wrap",
      gap: "10px",
      fontSize: "11px",
      marginTop: "6px",
    }}
  >
    {" "}
    {verified && <span style={{ color: "#28a745" }}>✔ VERIFIED</span>}{" "}
    <span style={{ color: res.dkim === "pass" ? "#28a745" : "#888" }}>
	  <i className={"fa " + (res['dkim']==='pass'?'fa-lock':'fa-unlock')}></i>{" "}
      DKIM{" "}
    </span>{" "}
    <span style={{ color: res.spf === "pass" ? "#28a745" : "#888" }}>      
	  <i className={"fa " + (res['spf']==='pass'?'fa-lock':'fa-unlock')}></i>{" "}
      SPF{" "}
    </span>{" "}
    <span style={{ color: res.dmarc === "pass" ? "#28a745" : "#888" }}>{" "}
	  <i className={"fa " + (res['dmarc']==='pass'?'fa-lock':'fa-unlock')}></i>{" "}
      DMARC{" "}
    </span>{" "}
	{arcPass && (
	<span style={{color:'#17a2b8'}}>
		<i className='fa fa-check'></i> ARC Sealed{" "}
	</span>
	)}{" "}
    {replyMismatch && (
      <span style={{ color: "#dc3545" }}> ⚠ REPLY-TO DIFFERENT DOMAIN </span>
    )}{" "}
    {returnMismatch && (
      <span style={{ color: "#dc3545" }}> ⚠ RETURN-PATH DIFFERENT </span>
    )}{" "}
    {suspiciousTld && (
      <span style={{ color: "#ff8800" }}> ⚠ SUSPICIOUS TLD </span>
    )}{" "}
    {infra && infra.origin == infra.via && infra.origin && infra.via && <span style={{ color: "#17a2b8" }}><i className="fa fa-map"></i> via {infra.origin} </span>}{" "}
	{infra && infra.origin != infra.via && infra.origin && infra.via && <span style={{ color: "#17a2b8" }}><i className="fa fa-map"></i> origin {infra.origin} via {infra.via} </span>}{" "}
	
    {firstIP && <span style={{ color: "#888" }}> IP {firstIP} </span>}{" "}
  </div>
);

  }

}

export default AuthStatusBridge;