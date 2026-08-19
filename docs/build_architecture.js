// docs/build_architecture.js — builds docs/CB_Admin_MCP_Architecture.docx.
//
// The document is a binary, so it ships WITH its builder: a .docx nobody can regenerate
// rots the first time the code moves underneath it.
//
// HOW TO RUN, from the repository root:
//
//     npm install docx                        # once; not vendored, it is a build-time dep
//     CB_ADMIN_PROFILE=workstation CB_ADMIN_READ_ONLY_MODE=false \
//         python docs/generate_tools_json.py > docs/tools.json
//     node docs/build_architecture.js
//
// The generate step refreshes the tool inventory (section 6) from the handler modules
// themselves, so the document's counts cannot drift from the code. docs/tools.json is
// committed so a reader can build without a working Python environment.
//
// INPUTS, all overridable by environment variable:
//   CB_DOC_DIAGRAMS  directory of arch01..arch08 PNGs   default docs/diagrams
//   CB_DOC_TOOLS     tool inventory JSON                default docs/tools.json
//   CB_DOC_OUT       output .docx                       default docs/CB_Admin_MCP_Architecture.docx
//
// The figures are generated separately: docs/diagrams-src/*.mmd are the Mermaid sources
// for arch01..arch08, and docs/make_arch_diagrams.py builds the fig01..fig10 matplotlib
// figures used by the older reference architecture set.
//
// AFTER EDITING, LOOK AT IT. Convert to PDF, rasterise, and read the pages — page breaks
// landing on an already-full page produce blank pages that no assertion catches:
//
//     soffice --headless --convert-to pdf docs/CB_Admin_MCP_Architecture.docx
//     pdftoppm -jpeg -r 80 CB_Admin_MCP_Architecture.pdf page

const fs = require("fs");
const d = require("docx");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, PageBreak,
  Table, TableRow, TableCell, WidthType, ShadingType, BorderStyle, ImageRun,
  TableOfContents, LevelFormat, PageOrientation, PositionalTab,
  PositionalTabAlignment, PositionalTabLeader, Footer, PageNumber,
} = d;

const path = require("path");

// Repo-relative by default. The PNGs are named archNN_* in docs/diagrams; this file
// refers to them by the NN_* stem, so the prefix is applied at read time.
const DIA = process.env.CB_DOC_DIAGRAMS || path.join(__dirname, "diagrams");
const REPO_PNG = (file) => path.join(DIA, "arch" + file);
const TOOLS_JSON = process.env.CB_DOC_TOOLS || path.join(__dirname, "tools.json");
const OUT_DOCX =
  process.env.CB_DOC_OUT ||
  path.join(__dirname, "CB_Admin_MCP_Architecture.docx");
const CW = 9360;                       // content width, Letter with 1" margins
const NAVY = "1F3864", BLUE = "2C6FB5", GREY = "5A5A5A", RED = "B3261E",
      AMBER = "8A6100", GREEN = "1B5E20";

const P = (text, o = {}) => new Paragraph({
  spacing: { after: o.after ?? 140, before: o.before ?? 0, line: 276 },
  alignment: o.align, indent: o.indent, border: o.border,
  children: [new TextRun({ text, bold: o.bold, italics: o.italics,
    size: o.size ?? 21, color: o.color ?? "222222", font: o.font })],
});

const Code = (text) => new Paragraph({
  spacing: { after: 40, before: 40 }, indent: { left: 240 },
  shading: { type: ShadingType.CLEAR, fill: "F4F6F8" },
  children: [new TextRun({ text, font: "Consolas", size: 18, color: "1A1A1A" })],
});

const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 340, after: 160 },
  children: [new TextRun({ text: t, bold: true, size: 32, color: NAVY })] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 260, after: 120 },
  children: [new TextRun({ text: t, bold: true, size: 25, color: BLUE })] });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 100 },
  children: [new TextRun({ text: t, bold: true, size: 22, color: "333333" })] });

const Bullet = (text, lvl = 0) => new Paragraph({
  numbering: { reference: "bul", level: lvl }, spacing: { after: 70, line: 276 },
  children: [new TextRun({ text, size: 21 })] });

const Step = (text, inst = 1) => new Paragraph({
  numbering: { reference: "num", level: 0, instance: inst }, spacing: { after: 80, line: 276 },
  children: [new TextRun({ text, size: 21 })] });

function cell(text, o = {}) {
  return new TableCell({
    width: { size: o.w, type: WidthType.DXA },
    shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined,
    margins: { top: 70, bottom: 70, left: 110, right: 110 },
    children: String(text).split("\n").map((line, i) => new Paragraph({
      spacing: { after: 0, line: 250 },
      alignment: o.align,
      children: [new TextRun({ text: line, bold: o.bold, size: o.size ?? 19,
        color: o.color ?? "222222", font: o.mono ? "Consolas" : undefined })],
    })),
  });
}

function table(headers, rows, widths, opts = {}) {
  const head = new TableRow({ tableHeader: true, children: headers.map((h, i) =>
    cell(h, { w: widths[i], bold: true, fill: NAVY, color: "FFFFFF", size: 19 })) });
  const body = rows.map((r, ri) => new TableRow({ children: r.map((c, i) =>
    cell(c, { w: widths[i], fill: ri % 2 ? "F7F9FC" : undefined,
      mono: opts.mono && opts.mono.includes(i),
      align: opts.center && opts.center.includes(i) ? AlignmentType.CENTER : undefined })) }));
  return new Table({ columnWidths: widths, rows: [head, ...body],
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    borders: {
      top:{style:BorderStyle.SINGLE,size:2,color:"BBBBBB"}, bottom:{style:BorderStyle.SINGLE,size:2,color:"BBBBBB"},
      left:{style:BorderStyle.SINGLE,size:2,color:"BBBBBB"}, right:{style:BorderStyle.SINGLE,size:2,color:"BBBBBB"},
      insideHorizontal:{style:BorderStyle.SINGLE,size:1,color:"DDDDDD"},
      insideVertical:{style:BorderStyle.SINGLE,size:1,color:"DDDDDD"} } });
}

function figure(file, caption, maxW = CW) {
  const dims = { "01_context.png":[1568,604], "02_pipeline.png":[1568,1148],
    "03_modules.png":[1568,1506], "04_trust.png":[1476,2584],
    "05_capella.png":[1568,784], "06_topology.png":[1568,276], "07_capella_connect.png":[1324,2324],
    "08_matrix.png":[1726,1285] }[file];
  let w = maxW, h = Math.round(maxW * dims[1] / dims[0]);
  const maxH = 11400;                                  // keep a figure on one page
  if (h > maxH) { h = maxH; w = Math.round(maxH * dims[0] / dims[1]); }
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 },
      children: [new ImageRun({ type: "png", data: fs.readFileSync(REPO_PNG(file)),
        transformation: { width: Math.round(w / 15), height: Math.round(h / 15) } })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 },
      children: [new TextRun({ text: caption, italics: true, size: 18, color: GREY })] }),
  ];
}

const Callout = (label, text, color) => new Paragraph({
  spacing: { before: 120, after: 160 }, indent: { left: 200, right: 200 },
  shading: { type: ShadingType.CLEAR, fill: color === RED ? "FDECEA" : color === AMBER ? "FFF8E1" : "E8F5E9" },
  border: { left: { style: BorderStyle.SINGLE, size: 18, color } },
  children: [ new TextRun({ text: label + "  ", bold: true, size: 20, color }),
              new TextRun({ text, size: 20, color: "222222" }) ],
});

const tools = JSON.parse(fs.readFileSync(TOOLS_JSON, "utf8"));
const modMeta = {
  backup:"Backup Service repositories and restore runs",
  buckets:"Bucket lifecycle, flush, settings",
  capella:"Capella v4 control plane: primitives, environment orchestration, fixtures",
  cluster:"Nodes, rebalance, failover, alerts, logs collection",
  collections:"Scopes and collections",
  diagnostics:"Query plan analysis, slow queries, index advisor",
  eight_x:"Couchbase Server 8.0+ only: vector indexes, conflict logs",
  encryption:"Encryption at rest, KMIP",
  eventing:"Eventing functions and deployment state",
  indexes:"GSI create, build, drop, list",
  mcp_status:"Server introspection: config, tool inventory, TLS state",
  search_admin:"Full-text search index administration",
  security:"Users, roles, password policy, audit settings",
  stats:"Metrics, system events, internal settings",
  xdcr:"Cross data centre replication",
};
const invRows = Object.entries(tools).map(([m, rows]) => {
  const c = (k) => rows.filter(([, cat]) => cat === k).length;
  return [m, String(rows.length), String(c("read")), String(c("write")), String(c("destructive")), modMeta[m]];
});
const tot = Object.values(tools).reduce((a, r) => a + r.length, 0);
const totR = Object.values(tools).flat().filter(([, c]) => c === "read").length;
const totW = Object.values(tools).flat().filter(([, c]) => c === "write").length;
const totD = Object.values(tools).flat().filter(([, c]) => c === "destructive").length;
invRows.push(["TOTAL", String(tot), String(totR), String(totW), String(totD), ""]);

const doc = new Document({
  creator: "Chris Ahrendt", title: "Couchbase Admin MCP Server - Architecture and Operations",
  description: "Architecture, tool breakdown, operating instructions and security model",
  numbering: { config: [
    { reference: "bul", levels: [
      { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 420, hanging: 220 } } } },
      { level: 1, format: LevelFormat.BULLET, text: "◦", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 840, hanging: 220 } } } } ] },
    { reference: "num", levels: [
      { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 420, hanging: 260 } } } } ] } ] },
  styles: { default: { document: { run: { font: "Calibri", size: 21 } } } },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } },
    footers: { default: new Footer({ children: [ new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [ new TextRun({ text: "Couchbase Admin MCP Server", size: 16, color: GREY }),
        new TextRun({ children: ["   -   ", PageNumber.CURRENT, " of ", PageNumber.TOTAL_PAGES], size: 16, color: GREY }) ] }) ] }) },
    children: [
      // ── TITLE ──
      new Paragraph({ spacing: { before: 2600, after: 120 }, alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Couchbase Admin MCP Server", bold: true, size: 56, color: NAVY })] }),
      new Paragraph({ spacing: { after: 400 }, alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Architecture, Tool Breakdown and Operating Instructions", size: 28, color: BLUE })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
        children: [new TextRun({ text: "208 tools  |  15 handler modules  |  two admin interfaces, one per instance", size: 22, color: GREY })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 1400 },
        children: [new TextRun({ text: "Revision 1.0  -  17 August 2026", size: 20, color: GREY })] }),
      Callout("Scope.", "This document describes the server as it stands on 17 August 2026. Section 9 records defects found by a four-pass adversarial scan on that date, including three that prevent shipped functionality from working. Read section 9 before deploying.", AMBER),
      new Paragraph({ children: [new PageBreak()] }),

      // ── TOC ──
      H1("Contents"),
      new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-3" }),
      new Paragraph({ children: [new PageBreak()] }),

      // ── 1 OVERVIEW ──
      H1("1. Overview"),
      P("The Couchbase Admin MCP Server exposes Couchbase administration to an AI agent or an operator console as a set of Model Context Protocol tools. It is an administration tool for production infrastructure, so its design is dominated less by what it can do than by what it refuses to do without an explicit, human-set decision."),
      P("Two structural facts govern everything that follows, and both are easy to get wrong on a first install."),
      Bullet("There are TWO admin interfaces: the Capella interface and the Enterprise self-managed interface. They differ in protocol, credential, authorization model and available operations."),
      Bullet("One running instance of this server manages ONE of them. To administer both, run two instances."),

      H2("1.1 Two admin interfaces, one per instance"),
      P("The two interfaces are not two views of the same thing. Capella is a multi-tenant control plane reached over an organization API key; a self-managed cluster is reached over the ns_server administration REST API with cluster administrator credentials. Capella deliberately does not expose ns_server to tenants, so the two tool families cannot be pointed at each other."),
      table(["", "Interface 1 - Capella", "Interface 2 - Enterprise self-managed"],
        [["Tools", "capella_*  (74)", "admin_* and cb_*  (134)"],
         ["Endpoint", "cloudapi.cloud.couchbase.com/v4", "https://<node>:18091  plus the SDK"],
         ["Credential", "Organization API key SECRET", "Cluster administrator, HTTP Basic"],
         ["Auth header", "Authorization: Bearer SECRET", "Basic CB_USERNAME / CB_PASSWORD"],
         ["Set", "CB_DEPLOYMENT=capella", "CB_DEPLOYMENT=self_managed"],
         ["Own guardrails", "Organization pin, project allowlist, name prefix, environment ceiling", "Egress allowlist, SQL++ statement guards, TLS verification, disabled-tool list"],
         ["Setup section", "2.4", "2.5"]],
        [1560, 3900, 3900], { mono: [0] }),
      Callout("One interface per instance. This is deployment guidance, not a code restriction.", "Set CB_DEPLOYMENT explicitly to capella or to self_managed and give that instance only the credentials for that interface. A third value, both, exists and loads everything - see section 2.3 for why it is not the recommended way to run and how auto can select it without being asked.", AMBER),

      H2("1.2 Two access paths into each instance"),
      P("Whichever interface an instance manages, it can be driven two ways: over the MCP transport in server.py, or through the Flask operator console in gui/gui_server.py. Both paths converge on the same authorization evaluation and the same handler set, and each path has its own authentication that can be turned off independently for sandbox work."),
      ...figure("08_matrix.png", "Figure 1 - Two interfaces, one per instance, each with two access paths. The policy layer and the handlers are shared between the paths; the authentication toggles are not."),
      Callout("Design consequence.", "Any control implemented in one access path must be implemented in the other. The scan in section 9 found five places where that is not true, and they account for both high-severity security findings. A single shared dispatch preamble would close the class permanently.", RED),

      H2("1.3 Tool prefixes"),
      P("Tools are prefixed by the system they reach. The split is not cosmetic: the planes disagree on protocol, credential, retry policy, TLS handling and pagination, so they are implemented by separate clients."),
      table(["Prefix", "Reaches", "Endpoint", "Credential"],
        [["admin_*", "Self-managed cluster (ns_server REST)", "https://<node>:18091", "HTTP Basic - CB_USERNAME / CB_PASSWORD"],
         ["capella_*", "Capella v4 control plane", "cloudapi.cloud.couchbase.com/v4", "Bearer - CAPELLA_API_KEY_SECRET"],
         ["cb_*", "Query service and server introspection", "Couchbase SDK / query", "Cluster credentials, or none"]],
        [1500, 2700, 2600, 2560], { mono: [0] }),
      P("cb_* is the only family that loads in both interfaces. SQL++ inference, system:indexes, EXPLAIN, ADVISE and the completed-requests advisors need no administration REST API at all, so they work unchanged against Capella."),

      // ── 2 SETUP ──
      H1("2. Setting up an instance"),
      P("Sections 2.4 and 2.5 are independent. Read the prerequisites, decide in 2.3 which interface this instance is for, then follow that one section and skip the other."),

      H2("2.1 Prerequisites, both interfaces"),
      Bullet("Python 3.10 to 3.14."),
      Bullet("Install the package and its extras: pip install -e \".[dev,http,gui,oauth]\""),
      Bullet("Copy .env.example to .env. Every knob is documented there; this section covers the ones without which nothing starts."),
      Bullet("Network reachability to the cluster's management port for self-managed, or to cloudapi.cloud.couchbase.com for Capella."),
      Callout("CB_ADMIN_PROFILE has no default, and that is deliberate.", "Startup fails if it is unset. The security posture is then one stated decision rather than the accidental sum of eight variables, and an unset profile cannot silently choose the permissive option. Both interfaces need it; both accept workstation or enterprise.", GREEN),

      H2("2.2 Two variables, two different questions"),
      P("Two variables get set at startup and they are the ones most often confused for each other, because one of their values is a word that means something else elsewhere in this document. They answer completely different questions."),
      table(["The question it answers", "Variable", "Values", "What it changes"],
        [["Is a human watching at the moment of the call?", "CB_ADMIN_PROFILE", "workstation | enterprise", "How much is refused, and what counts as approval. Nothing about which cluster."],
         ["What does this instance administer?", "CB_DEPLOYMENT", "capella | self_managed", "Which tools exist at all. Nothing about security posture."]],
        [3000, 2300, 2100, 1960], { mono: [1, 2] }),
      Callout("The word enterprise means two unrelated things, and only one of them is a profile.", "CB_ADMIN_PROFILE=enterprise means unattended: an agent chain acting on an IdP-issued token with no person at the keyboard. It says nothing about Couchbase. The Enterprise self-managed INTERFACE means Couchbase Server Enterprise Edition, self-hosted, reached over ns_server - and that is CB_DEPLOYMENT=self_managed, never CB_ADMIN_PROFILE=enterprise. The two are set independently and either profile is valid with either interface.", RED),
      P("There is also no capella profile, and there should not be. Whether you are administering Capella is a question about the target; whether a person is present to approve a bucket deletion is a question about the caller. Collapsing them would mean you could not run a laptop against Capella, or an unattended pipeline against a lab cluster, and both are ordinary."),
      H3("2.2.1 Why the profile is named after the client, not the cluster"),
      P("workstation describes where the CALLER is: a developer's laptop, a local process or a container driven by Claude Desktop over stdio. There is no identity provider and no token, so identity is the OS user, nothing is network-exposed, and confirm: true is a real second look by a real person because the MCP client puts each tool call in front of them."),
      P("enterprise describes the opposite caller: a human pushes code, a workflow-manager agent notices, a child agent performs the admin task, and nobody says OK at the moment of action - correctly, because the authorization happened when the IdP issued that child a token carrying the automation scope. No human is present by design, so confirm: true means nothing here; the model supplies it. What carries the weight instead is the token's scopes, the allowlists and the audit record."),
      P("Those two callers want opposite defaults. Before the profile existed they were expressed as about ten independent variables with no coherence check, which is how you get fail-closed authorization that blocks a laptop, or an unauthenticated console that is fine on loopback and catastrophic in a data centre. The profile makes it one stated decision."),
      H3("2.2.2 The four combinations, all of them supported"),
      table(["Profile", "Interface", "What this instance is"],
        [["workstation", "capella", "A laptop administering a Capella organization, production included. Claude Desktop on stdio, organization API key, a person approving each destructive call."],
         ["workstation", "self_managed", "A laptop administering a local or lab cluster. The most common development setup."],
         ["enterprise", "capella", "An unattended pipeline provisioning or tearing down Capella environments on an OAuth token."],
         ["enterprise", "self_managed", "An unattended pipeline administering a data-centre cluster on an OAuth token."]],
        [1700, 1700, 5960], { mono: [0, 1] }),
      H3("2.2.3 What the profile actually does, rather than what it forbids"),
      P("A profile fills in variables you did not set, and never overrides one you did - an operator who has made a decision keeps it. So the profile only closes the gap between a deliberate choice and not having thought about it."),
      table(["Variable", "workstation sets", "enterprise sets", "Because"],
        [["CB_ADMIN_TRANSPORT", "stdio", "(unset)", "A laptop has a client on a pipe; a container is reached over HTTP."],
         ["CB_ADMIN_HOST", "127.0.0.1", "(unset)", "Nothing on a laptop should be reachable off the box."],
         ["CB_ADMIN_HTTP_REQUIRE_AUTH", "false", "true", "There is no IdP on a laptop, so demanding a token would fail closed for no gain."],
         ["OAUTH_ENABLED", "(unset)", "true", "Unattended authorization IS the token."],
         ["CB_GUI_INSECURE_NO_AUTH", "1", "0", "Loopback console driven by the same person, versus a console that must sit behind SSO."],
         ["CB_ADMIN_READ_ONLY_MODE", "false", "false", "Both are for doing work. The gates that matter are downstream."],
         ["CB_ADMIN_EGRESS_ALLOW_ANY", "false", "false", "Fails closed in both. The operator names where the cluster may be pointed."],
         ["CB_ADMIN_LOG_SINKS", "(unset)", "stderr,file", "Unattended, the log is the only record that an action happened."],
         ["CB_ADMIN_AUDIT_FILE", "(unset)", "/var/log/couchbase-admin-mcp/audit.log", "An absolute path: a relative one lands in whatever the container's CWD is and is lost on restart."]],
        [2700, 1500, 2300, 2860], { mono: [0, 1, 2] }),
      Callout("Note the two rows that are identical in both profiles.", "Read-only mode is off and egress fails closed in workstation as well as enterprise. The profile is not a safe/unsafe switch - it is a description of who is calling, and some controls do not depend on that at all. What the profile will not do in either direction is let an incoherent pair through silently: section 2.6 lists the combinations that are fatal at startup.", GREEN),
      H2("2.3 Decide which interface this instance manages"),
      P("Set CB_DEPLOYMENT explicitly. It selects which tool families are registered at all, and a tool that cannot succeed is better absent than present and broken - an agent cannot misroute to a tool it never sees."),
      table(["CB_DEPLOYMENT", "Loads", "Use it when"],
        [["capella", "capella_* and cb_*  (74 + shared)", "This instance administers a Capella organization. RECOMMENDED for Capella."],
         ["self_managed", "admin_* and cb_*  (134)", "This instance administers a self-managed cluster. RECOMMENDED for Enterprise."],
         ["both", "Everything, gated nothing", "Not recommended. See the warning below."],
         ["auto", "Inferred from the credentials present", "Not recommended in a deployment. See the warning below."]],
        [1900, 3000, 4460], { mono: [0] }),
      Callout("auto can resolve to both without being asked, so do not leave it unset.", "detect_mode() infers: a Capella host in CB_CONNECTION_STRING gives capella; CAPELLA_API_KEY_SECRET with no connection string gives capella; CAPELLA_API_KEY_SECRET together with a non-Capella connection string gives BOTH. So an instance that has a Capella key left over in its .env and a self-managed connection string loads all 208 tools, and the one-interface-per-instance boundary is gone with no warning at the point of use. Naming the mode removes the inference.", RED),
      Callout("Why one interface per instance is the right default anyway.", "It keeps one credential set per process, so a compromise or a misconfiguration reaches one plane rather than two. It makes the loaded tool list an assertion you can check with cb_mcp_list_tools rather than a superset to search. And the two interfaces want different guardrails - a project allowlist means nothing to a self-managed cluster, and an egress allowlist means nothing to the v4 control plane - so combining them produces a configuration where half the guardrails are inert.", GREEN),

      // ── 2.3 CAPELLA ──
      H2("2.4 Setup A - the Capella interface"),
      P("Capella needs materially more setup than a local cluster, and the two most common failures are both configuration rather than code. Read 2.4.1 before creating anything."),
      Callout("admin_* tools do not work against Capella, and that is not a defect.", "Capella does not expose the ns_server admin REST API to tenants, and a Capella database credential carries bucket-scoped data roles and never Full Admin. So the 134 admin_* tools are unloaded in capella mode. Their Capella equivalents are the capella_* family.", AMBER),
      H3("Steps"),
      Step("In Capella, go to Settings then API Keys and create a key. Give it the least role that works: reads need projectViewer, writes need projectManager or organizationOwner. The key's roles are an independent authorization layer - this server's guardrails and Capella RBAC are both in force, and the stricter one wins.", 2),
      Step("Put your egress IP in the KEY's allowed IPs during creation. If you are on VPN it is the VPN's egress, not your office range.", 2),
      Step("Copy the SECRET. Capella shows it once and never again. It is the long value - the 32-character alphanumeric string beside it is the key id and will not authenticate.", 2),
      Step("Set the profile, the mode and the control-plane credential.", 2),
      Code("CB_ADMIN_PROFILE=workstation             # is a human present? see 2.2"),
      Code("CB_DEPLOYMENT=capella                    # what does it administer? see 2.3"),
      Code("CAPELLA_API_KEY_SECRET=<the long secret>"),
      Code("CAPELLA_ORG_ID=<organization uuid>       # pins the org; a conflicting"),
      Code("                                         # caller-supplied value is refused"),
      Step("If you intend any destructive Capella operation, set the guardrails. Without an allowlist the server refuses all destruction, which is the correct out-of-box posture but will look like a bug if you were not expecting it.", 2),
      Code("CAPELLA_ALLOWED_PROJECTS=<test project uuid>   # production NOT listed"),
      Code("CAPELLA_ENV_NAME_PREFIX=mcptest-               # load-bearing: teardown and"),
      Code("                                               # reap refuse anything lacking it"),
      Code("CAPELLA_MAX_ENVIRONMENTS=10                    # spend ceiling"),
      Code("CAPELLA_ENV_TTL_HOURS=8                        # what reap collects"),
      Step("For data-plane work - cb_* tools, or fixture export and import - additionally create a cluster access credential, add your IP to the CLUSTER's Allowed IP Addresses, and set the connection string. For fixtures, also enable the Data API on the cluster; it is off by default.", 2),
      Code("CB_CONNECTION_STRING=couchbases://cb.xxxxx.cloud.couchbase.com"),
      Code("CB_USERNAME=<cluster access username>"),
      Code("CB_PASSWORD=<cluster access password>"),
      Step("Start it, then confirm the posture the server actually adopted rather than the one you intended.", 2),
      Code("python server.py            # then call cb_mcp_status"),
      H3("2.4.1 Two credentials, two IP allowlists, and they are not interchangeable"),
      ...figure("07_capella_connect.png", "Figure 2 - Capella connectivity. Two planes, two credentials, two independent IP allowlists.", 6400),
      table(["", "Control plane", "Data plane"],
        [["Used by", "capella_* tools", "cb_* tools, fixture export and import"],
         ["Credential", "Organization API key SECRET", "Cluster access credential"],
         ["Variable", "CAPELLA_API_KEY_SECRET", "CB_USERNAME and CB_PASSWORD"],
         ["Created in", "Settings - API Keys", "Databases - cluster - Cluster Access"],
         ["Endpoint", "cloudapi.cloud.couchbase.com/v4", "cb.xxxxx.cloud.couchbase.com"],
         ["Auth", "Authorization: Bearer SECRET", "SCRAM over couchbases:// TLS"],
         ["IP allowlist", "On the API KEY itself, under Organization - API Keys. Often fixed at creation.", "The cluster's Allowed IP Addresses, under the cluster's settings. Editable any time."]],
        [1500, 3900, 3960]),
      Callout("The two IP allowlists are separate, and satisfying one does not satisfy the other.", "This is the single most expensive mistake available here. Adding your IP to the cluster's Allowed IP Addresses does nothing for the v4 control plane, because that call never consults it. The API key carries its own allowlist, and on many Capella versions it is fixed at key creation - if the key's page offers no way to edit it, the key must be replaced.", RED),
      H3("2.4.2 Verify, cheapest call first"),
      Step("capella_organizations_list. The only v4 call that needs nothing but the key, so it is the fastest proof the credential works. Everything else is rooted at an organization id.", 3),
      Step("capella_projects_list, then capella_clusters_list. These confirm the key's roles reach the project you intend to work in.", 3),
      Step("cb_mcp_status and cb_mcp_list_tools. Confirm the mode resolved to capella and that no admin_* tools loaded.", 3),

      // ── 2.4 SELF-MANAGED ──
      new Paragraph({ children: [new PageBreak()] }),
      H2("2.5 Setup B - the Enterprise self-managed interface"),
      P("Shorter than Capella: one credential, one endpoint, no organization or project hierarchy. The care here goes into the egress allowlist and TLS, because this credential is a cluster administrator."),
      H3("Steps"),
      Step("Create or obtain a cluster administrator credential. Full Admin is what the admin_* family assumes; a lesser role produces 403s from ns_server rather than from this server, which is harder to read.", 6),
      Step("Set the profile, the mode and the cluster credential.", 6),
      Code("CB_ADMIN_PROFILE=workstation             # is a human present? see 2.2"),
      Code("CB_DEPLOYMENT=self_managed               # what does it administer? see 2.3"),
      Code("CB_CONNECTION_STRING=couchbase://localhost   # or couchbases:// for TLS"),
      Code("CB_USERNAME=Administrator"),
      Code("CB_PASSWORD=..."),
      Step("Leave TLS verification on. CB_ADMIN_TLS_INSECURE disables certificate and hostname checking, and this server sends administrator credentials on every call, so turning it off makes them MITM-able. The enterprise profile refuses to start with it set.", 6),
      Step("Set the egress allowlist before using any tool that takes a destination host - log collection upload, XDCR remote reference, backup target. Without it the cluster could be pointed at any public host, including as the destination for a full diagnostic bundle.", 6),
      Code("CB_ADMIN_EGRESS_ALLOWED_HOSTS=backup.internal,logs.internal"),
      Code("# CB_ADMIN_EGRESS_ALLOW_ANY=true          # refused by the enterprise profile"),
      Step("Optionally narrow the surface further. CB_ADMIN_DISABLED_TOOLS removes named tools outright, and configuration can only tighten the hard ceiling, never loosen it.", 6),
      Code("CB_ADMIN_DISABLED_TOOLS=admin_bucket_delete,admin_cluster_failover"),
      Step("Start it, then confirm the posture the server actually adopted rather than the one you intended.", 6),
      Code("python server.py            # then call cb_mcp_status"),
      H3("2.5.1 Verify"),
      Step("cb_mcp_status. Read the profile, read_only_mode and tls_verify_disabled, and confirm the mode resolved to self_managed.", 7),
      Step("cb_mcp_list_tools. Confirm no capella_* tools loaded. If any did, CAPELLA_API_KEY_SECRET is still in the environment and the mode was inferred as both.", 7),
      Step("admin_cluster_info, then admin_buckets_list. These prove the Basic credential reaches ns_server with an administrator role.", 7),

      // ── 2.5 SECURITY TOGGLES ──
      new Paragraph({ children: [new PageBreak()] }),
      H2("2.6 Turning security on and off for a sandbox"),
      P("Both interfaces, and both access paths within each, can be relaxed for sandbox testing. The toggles are per path, not per interface: the same variables apply whichever interface the instance manages. Two properties make this safe to offer at all - each relaxation is a named variable that has to be set deliberately, and the enterprise profile refuses to start when the dangerous ones are set."),
      table(["Variable", "Path / layer", "Sandbox value", "Default", "Enterprise profile"],
        [["CB_ADMIN_HTTP_REQUIRE_AUTH", "Path 1 - MCP over HTTP", "false", "true on http", "FATAL if not true"],
         ["OAUTH_ENABLED", "Path 1 - token validation", "false", "off on stdio", "Needs issuer + audience"],
         ["OAUTH_SKIP_VERIFY", "Path 1 - token validation", "never", "false", "FATAL in EVERY profile"],
         ["CB_GUI_INSECURE_NO_AUTH", "Path 2 - operator console", "true", "false", "FATAL if true"],
         ["CB_ADMIN_READ_ONLY_MODE", "Shared policy layer", "false", "true", "Allowed; audited"],
         ["CB_ADMIN_ALWAYS_CONFIRM", "Shared policy layer", "false", "true", "Allowed; audited"],
         ["CB_ADMIN_DRY_RUN", "Shared policy layer", "true to preview", "false", "Allowed"],
         ["CB_ADMIN_TLS_INSECURE", "Outbound to cluster", "true", "false", "FATAL if true"],
         ["CB_ADMIN_EGRESS_ALLOW_ANY", "Outbound egress guard", "true", "false", "FATAL if true"],
         ["CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE", "Capella guardrails", "true", "false", "Allowed; audited"],
         ["CB_ADMIN_WORKSTATION_CONTAINER_BIND", "Workstation bind check", "true", "unset", "Not consulted"]],
        [3000, 2200, 1500, 1300, 1360], { mono: [0, 2, 3] }),
      Callout("The most privileged configuration in the codebase is reachable by setting the profile that sounds safest.", "CB_ADMIN_PROFILE=workstation with an HTTP transport bound to 0.0.0.0 gives an unauthenticated admin server, reachable from the network, on which every destructive tool completes for any caller willing to send confirm: true. The workstation relaxations are all justified by the claim that a human is at the client and no port is exposed, so a non-loopback bind now fails at startup unless CB_ADMIN_WORKSTATION_CONTAINER_BIND acknowledges it. The realistic path to this is not an attacker choosing these values; it is an operator copying a dev compose file into a data centre.", RED),
      H3("A sandbox .env that relaxes both paths"),
      Code("CB_ADMIN_PROFILE=workstation             # human present; enterprise refuses the below"),
      Code("CB_DEPLOYMENT=capella                    # or self_managed - pick ONE"),
      Code("CB_ADMIN_TRANSPORT=streamable_http"),
      Code("CB_ADMIN_HOST=127.0.0.1                  # loopback, or set the bind ack"),
      Code("CB_ADMIN_HTTP_REQUIRE_AUTH=false         # path 1 open"),
      Code("CB_GUI_INSECURE_NO_AUTH=true             # path 2 open"),
      Code("CB_ADMIN_READ_ONLY_MODE=false            # write tools load"),
      Code("CB_ADMIN_ALWAYS_CONFIRM=false            # no per-call second look"),
      Code("CB_ADMIN_AUDIT_FILE=./audit.log          # keep this even in a sandbox"),
      Callout("Going back to secure is one variable, and it will tell you what it does not like.", "Set CB_ADMIN_PROFILE=enterprise and start. Validation refuses the eight combinations that cannot be secure - HTTP auth off, console auth off, egress unrestricted, TLS verification off, missing OAUTH_ISSUER, missing OAUTH_AUDIENCE, no durable audit sink, and OAUTH_SKIP_VERIFY - and the startup error names each one and why. Fix them until it starts, and the posture is coherent rather than merely configured.", GREEN),

      H2("2.7 Connecting a client"),
      P("Stdio is simplest for a desktop client; a long-running container should use streamable HTTP. The configuration below is per instance, so two instances mean two entries with different names and different environment blocks."),
      Code("{ \"mcpServers\": {"),
      Code("    \"couchbase-capella\": {"),
      Code("      \"command\": \"python\", \"args\": [\"/path/to/server.py\"],"),
      Code("      \"env\": { \"CB_ADMIN_PROFILE\": \"workstation\","),
      Code("               \"CB_DEPLOYMENT\": \"capella\","),
      Code("               \"CAPELLA_API_KEY_SECRET\": \"...\" } },"),
      Code("    \"couchbase-enterprise\": {"),
      Code("      \"command\": \"python\", \"args\": [\"/path/to/server.py\"],"),
      Code("      \"env\": { \"CB_ADMIN_PROFILE\": \"workstation\","),
      Code("               \"CB_DEPLOYMENT\": \"self_managed\","),
      Code("               \"CB_CONNECTION_STRING\": \"couchbase://localhost\","),
      Code("               \"CB_USERNAME\": \"Administrator\", \"CB_PASSWORD\": \"...\" } } } }"),
      Callout("Keep the credential sets disjoint.", "The Capella entry has no CB_USERNAME and the Enterprise entry has no CAPELLA_API_KEY_SECRET. That is what makes CB_DEPLOYMENT redundant rather than load-bearing: even if the mode were inferred, neither instance has the credentials to reach the other interface. Set the mode anyway, so the tool list is an assertion.", GREEN),
      P("For the operator console, run gui/gui_server.py against the same .env. It is the second access path into the same instance, not a second instance, and it shares the policy layer and the audit trail."),

      H2("2.8 Troubleshooting"),
      table(["Symptom", "What it means", "What to do"],
        [["Startup fails naming CB_ADMIN_PROFILE", "It has no default, by design.", "Set workstation or enterprise."],
         ["401 with code 1001 from Capella", "Capella returns this for BOTH a bad secret and an IP-allowlist rejection. The status cannot discriminate between them.",
          "Check the secret's length first - the key id is 32 characters, the secret is longer. Then check the KEY's allowlist, not the cluster's."],
         ["403 from Capella", "Authenticated, but the key's roles do not permit the call.", "Raise the key's role on the target project, or use a key that has one."],
         ["Organization or project cannot be resolved", "The key may have project roles but no organization role, so it cannot read /v4/organizations.",
          "Supply the organization, project and cluster ids explicitly from the console URL."],
         ["404 with plain text 'page not found'", "The route does not exist. This is a wrong path, not a missing resource.",
          "Correct the path. Do not conflate this with the next row."],
         ["404 carrying a JSON code", "The route matched and the handler ran; the object genuinely is not there.", "The path is right. Check the id."],
         ["admin_* tools are missing", "Expected in capella mode. They are unloaded because ns_server is not reachable.", "Nothing. Use the capella_* equivalents."],
         ["capella_* tools are missing", "The mode did not resolve to capella.", "Set CB_DEPLOYMENT=capella and confirm CAPELLA_API_KEY_SECRET is set."],
         ["All 208 tools loaded when you expected 74 or 134", "The mode resolved to both, most likely from auto with a leftover Capella key.",
          "Set CB_DEPLOYMENT explicitly and remove the credentials for the other interface."],
         ["Enterprise profile refuses to start", "One of the eight incoherent combinations is set.", "Read the error - it names each variable and why. Section 2.6 lists them."]],
        [2400, 3500, 3460]),
      Callout("A verified detail worth knowing before you plan a migration.", "Capella v4 restore is same-cluster only: the body's sourceClusterId must match the cluster in the URL path, and a targetClusterId is silently ignored. There is no API path for backing up cluster A and restoring into cluster B. Section 7 records the probe that established this.", AMBER),
      // ── 3 ARCHITECTURE ──
      H1("3. Architecture"),
      H2("3.1 System context"),
      P("The four destinations on the right of Figure 3 are the only outbound targets the server legitimately has. Anything else a tool tries to reach is a server-side request forgery, which is what the egress guard exists to refuse."),
      ...figure("01_context.png", "Figure 3 - System context. What the server talks to, and with which credential."),
      new Paragraph({ children: [new PageBreak()] }),
      H2("3.2 Module map"),
      ...figure("03_modules.png", "Figure 4 - Module map. Both entry points converge on one policy layer and one handler set."),
      P("profile_config writes into the process environment at import time, which makes import order load-bearing: every consumer of a profile-supplied variable must import after it. Both entry points do this correctly, verified module by module."),
      H2("3.3 The authorization pipeline"),
      P("Figure 5 is the sequence every tool call passes through. The order is not arbitrary - each gate assumes the previous one has run."),
      ...figure("02_pipeline.png", "Figure 5 - Authorization pipeline. One audit record is emitted per decision, whatever the decision was."),
      H3("Why the order matters"),
      Bullet("The hard ceiling runs first and unconditionally. A tool named in it cannot be satisfied by confirm: true or by an automation scope. This is what makes unattended automation safe to offer at all."),
      Bullet("Configuration can only tighten the ceiling, never loosen it."),
      Bullet("Dry run runs after every gate, so a preview cannot be used to inspect a tool the caller may not call."),
      Bullet("Redaction is applied on the way out, in both the success and the error path, so a secret echoed by the cluster does not reach the model."),
      new Paragraph({ children: [new PageBreak()] }),
      H2("3.4 Trust boundaries"),
      P("The rule that matters: no policy value is readable or writable from a tool argument. A caller provably cannot self-promote out of the sandbox. This was tested directly against the organization pin, the project allowlist, the name prefix and the automation claim, and all four hold."),
      ...figure("04_trust.png", "Figure 6 - Trust boundaries and the validation each input class must pass.", 5600),
      P("The semi-trusted row is the subtle one. A Capella cluster description carrying an ownership marker is written by this server but editable by anyone with Capella access, so ownership decisions re-fetch and re-validate rather than trusting a cached marker."),
      new Paragraph({ children: [new PageBreak()] }),
      H2("3.5 Deployment topologies"),
      ...figure("06_topology.png", "Figure 7 - The two profiles. Workstation assumes a human on stdio; enterprise assumes an unattended OAuth chain."),
      P("The profile and the interface are two independent axes, and they are set by two different variables. The profile decides how much is refused; the interface decides what is loaded. Either profile is valid with either interface, so there are four supported combinations and each is one instance."),
      table(["Setting", "Values", "Effect"],
        [["CB_ADMIN_PROFILE", "workstation | enterprise", "Security posture. No default - fatal if unset."],
         ["CB_DEPLOYMENT", "capella | self_managed", "Which interface this instance manages. Set it explicitly."],
         ["CB_ADMIN_READ_ONLY_MODE", "true (default) | false", "Whether write tools load at all."],
         ["CB_ADMIN_TRANSPORT", "stdio | streamable_http", "Also determines whether a human is assumed present."]],
        [2600, 2600, 4160], { mono: [0, 1] }),
      H3("3.5.1 The both mode, and why it is not in the table above"),
      P("deployment.py accepts a third value, both, which loads all 208 tools and gates nothing. It is a real code path with a real use - a single hybrid session driving a self-managed cluster and a Capella organization at once - and tests cover it. It is nevertheless not how this server should be deployed, for three reasons."),
      Bullet("It puts two credential sets in one process. A compromise or a misconfiguration then reaches two planes instead of one."),
      Bullet("It makes the loaded tool list a superset to search rather than an assertion to check. In a single-interface instance, a capella_* tool appearing where you expected admin_* is itself the error message."),
      Bullet("Half the guardrails go inert. CAPELLA_ALLOWED_PROJECTS constrains nothing on a self-managed cluster and CB_ADMIN_EGRESS_ALLOWED_HOSTS constrains nothing on the v4 control plane, so a configuration that looks fully guarded is only half guarded, and which half depends on which tool is called."),
      Callout("The path into both is not choosing it; it is not choosing anything.", "detect_mode() resolves CAPELLA_API_KEY_SECRET plus a non-Capella CB_CONNECTION_STRING to both. So an instance intended for a self-managed cluster, whose .env still carries a Capella key from earlier work, silently loads all 208 tools. The inference is defensible in isolation - an operator who configures both plainly intends both - but it means the one-interface-per-instance boundary can be lost without anyone deciding to lose it. Naming the mode removes the inference entirely, which is why section 2.3 says to set it even when the credentials already make it unambiguous.", RED),
      P("CB_DEPLOYMENT_GATE=false is a further escape hatch with the same effect as both. Prefer both if you genuinely need this, because it is the explicit spelling and it appears in the startup summary."),

      // ── 4 TOOLS ──
      H1("4. Tool breakdown"),
      P("208 tools across 15 handler modules. Categories are mutually exclusive and are taken from each tool's MCP annotations: a read tool declares readOnlyHint, a destructive tool declares destructiveHint, and everything else is a write."),
      table(["Module", "Tools", "Read", "Write", "Destr.", "Covers"],
        invRows, [1750, 780, 700, 730, 780, 4620], { mono: [0], center: [1, 2, 3, 4] }),
      Callout("Classification is enforced, not documented.", "All 208 tools were compared between the scope gate's read/write predicate and the compatibility shim's. Zero disagreements, and the structural relationship can only ever be stricter, so a future divergence fails closed rather than open.", GREEN),
      H2("4.1 The Capella family in detail"),
      P("The Capella side has three shipped tiers plus a quarantine. Conflating them is the most likely way to misuse it."),
      ...figure("05_capella.png", "Figure 8 - Capella layering. Nothing enters the shipped registry without live verification."),
      Bullet("Primitives (spec.py, 61 ops) are thin - one tool per v4 operation, no orchestration. Use when you know exactly which call you want."),
      Bullet("Orchestration (environment.py, 8 tools) sequences primitives and enforces ordering constraints the individual tool descriptions do not expose: an App Service must be deleted before its cluster; a resume must be polled to healthy."),
      Bullet("Fixtures (fixture.py, 4 tools) are defined but their handlers deliberately refuse, pending live verification of two response shapes. See the fixture design note."),
      Bullet("Pending (spec_pending.py, 22 ops) sit outside the shipped registry, so no tools are generated from them. A test asserts the live-verification record and the registry agree exactly - that test exists because a commit message once claimed all paths were verified while ten were not."),

      // ── 5 SECURITY MODEL ──
      new Paragraph({ children: [new PageBreak()] }),
      H1("5. Security model"),
      H2("5.1 The layers"),
      table(["Layer", "Control", "Defeated by"],
        [["1", "Read-only mode, on by default. Write tools are not registered.", "An operator setting CB_ADMIN_READ_ONLY_MODE=false"],
         ["1a", "Dry run. Preview a write without performing it.", "Not a control - an aid. Runs after every gate."],
         ["2", "Confirmation. confirm: true from a human, or an automation scope from a token.", "Nothing, for a tool in the ceiling"],
         ["3", "Hard ceiling. CB_ADMIN_ALWAYS_CONFIRM names tools that neither confirm nor automation can satisfy.", "Nothing set at request time"],
         ["4", "Capella guardrails: organization pin, project allowlist, resource name prefix, environment ceiling.", "Nothing set at request time"],
         ["5", "Egress guard. Caller-supplied destinations are refused unless allowlisted.", "An explicit allowlist entry"]],
        [700, 5200, 3460], { center: [0] }),
      H2("5.2 Identity"),
      Bullet("JWT validation requires exp, iss and sub, plus aud when configured. Algorithm confusion, unsigned tokens, HS256-signed-with-the-public-key, empty issuer and kid confusion were each tested and each fails closed."),
      Bullet("Scopes are couchbase-admin-mcp:read, :write and :automation. A read-scoped token cannot reach a write tool and vice versa; full access needs both."),
      Bullet("Automation can only come from a token scope. It cannot be claimed in a request body - that was closed and is pinned by a test."),
      Bullet("The token cache is keyed by hash, never stores the raw credential, never outlives the token's own expiry, and is bounded."),
      H2("5.3 Audit"),
      P("One JSON record per decision, from both dispatch paths, written as a single line so that carriage returns in any field are escaped by the encoder rather than by a filter. Records carry the decision, the tool, the resolved principal, the deployment mode and a caller-supplied correlation id that is sanitised and never consulted for authorization."),

      // ── 6 OPERATIONS ──
      H1("6. Operating instructions"),
      H2("6.1 Routine checks"),
      Step("Confirm the effective posture, not the intended one: run cb_mcp_status and read tls_verify_disabled, read_only_mode and the profile.", 4),
      Step("Confirm the loaded tool inventory matches the deployment mode: run cb_mcp_list_tools.", 4),
      Step("Verify the audit sink is durable. In the enterprise profile CB_ADMIN_AUDIT_FILE is mandatory and startup fails without it.", 4),
      H2("6.2 Before a destructive change"),
      Step("Run the tool with dry_run: true and read the preview.", 5),
      Step("Confirm the target: for Capella, confirm the project is on the allowlist and the resource name carries the configured prefix.", 5),
      Step("Perform the change with confirm: true.", 5),
      Step("Confirm the audit record was written with the expected principal and correlation id.", 5),
      Callout("Do not put a password in a dry-run call today.", "Finding SEC-2 in section 9: the preview echoes caller-supplied argument values in prose, and that prose is not redacted. Until it is fixed, a dry run of a user-creation tool puts the password in the model's context and in the console response.", RED),
      H2("6.3 Capella environment lifecycle"),
      table(["Step", "Tool", "Notes"],
        [["Provision", "capella_env_ensure", "Creates cluster and optional App Service, ordered correctly"],
         ["Check", "capella_env_status", "Asynchronous - poll until healthy"],
         ["Park", "capella_env_park", "Stops spend, keeps data. Deletes replications - see below"],
         ["Resume", "capella_env_resume", "Asynchronous - poll until healthy"],
         ["Destroy", "capella_env_teardown", "App Service first, then cluster. Irreversible"],
         ["Sweep", "capella_env_reap", "Collects environments past their TTL"]],
        [1200, 2800, 5360], { mono: [1] }),
      Callout("Park and resume overstate what they preserve.", "Turning a Capella cluster off deletes its XDCR replications on both sides. Data, schema, indexes, users, allowlists and private endpoints all survive; replications do not, and must be recreated. Cost falls but is not near zero - storage, backups, transfer and private endpoints keep billing, and there is a hard 30-day ceiling before Capella restarts the cluster automatically.", AMBER),

      // ── 7 CAPELLA FACTS ──
      new Paragraph({ children: [new PageBreak()] }),
      H1("7. Verified Capella behaviour"),
      P("Established by live probe on 17 August 2026 against a Field Engineering organization, on a cluster running Couchbase Server 8.0.2. These supersede any inference from the rendered API reference, whose section names do not map to URL segments."),
      table(["Question", "Answer"],
        [["Does cross-cluster restore exist in v4?",
          "No. POST .../clusters/{id}/backups/{backup_id}/restore requires the body's sourceClusterId to MATCH the cluster in the path (error 5026), and a targetClusterId is silently ignored. A cluster's backup restores only into itself."],
         ["Backups and replications endpoints", "Both answer 200. Five backup operations and the replication list are confirmed and ready to promote."],
         ["Eventing path", "clusters/{id}/eventing/functions does not route. clusters/{id}/eventingFunctions does."],
         ["Query index path", "clusters/{id}/queryIndexes does not route. clusters/{id}/queryService/indexes does."],
         ["What does Capella return for an unroutable path?", "Plain-text 404 page not found. A 404 carrying a JSON domain code means the route matched and the handler ran - the two must not be conflated."],
         ["Does the API key allowlist failure present as 403?", "No, as 401 with code 1001, the same status as a bad secret. The status cannot discriminate between the two."]],
        [2700, 6660]),
      Callout("Cross-cluster restore is the one requirement with no API workaround.", "It is why the fixture layer exists: a manifest plus a JSON Lines payload, exported and imported over the Data API, is the only API-driven way to move a dataset from one Capella cluster to another. See the fixture design note.", AMBER),

      // ── 8 CONFIG ──
      H1("8. Configuration reference"),
      P("The full set is documented in .env.example, which is the authoritative list. The variables below are the ones that change behaviour materially."),
      table(["Variable", "Purpose"],
        [["CB_ADMIN_PROFILE", "workstation or enterprise. No default. Fatal if unset."],
         ["CB_DEPLOYMENT", "Which admin interface this instance manages: capella or self_managed. Set it explicitly - see 3.5.1 on both and auto."],
         ["CB_ADMIN_READ_ONLY_MODE", "Default true. When true, write tools are not registered."],
         ["CB_ADMIN_ALWAYS_CONFIRM", "The hard ceiling. Comma-separated tool names that neither confirm nor automation satisfies."],
         ["CB_ADMIN_DISABLED_TOOLS", "Tools to withhold entirely."],
         ["CB_ADMIN_EGRESS_ALLOWED_HOSTS", "The only outbound destinations a caller may name. Empty means deny all."],
         ["CB_ADMIN_AUDIT_FILE", "Durable audit sink. Mandatory in the enterprise profile."],
         ["CB_ADMIN_TLS_INSECURE", "Disables certificate verification. Surfaced by cb_mcp_status and warned about at startup."],
         ["CAPELLA_API_KEY_SECRET", "The API key SECRET, not its id. Read by the shipping client."],
         ["CAPELLA_ORG_ID", "Organization pin. A conflicting caller-supplied value is refused, not honoured."],
         ["CAPELLA_ALLOWED_PROJECTS", "Destructive Capella operations are confined to these projects. Empty means refuse all destruction."],
         ["CAPELLA_ENV_NAME_PREFIX", "Resources created by this server carry it; destructive operations refuse anything lacking it."],
         ["CAPELLA_MAX_ENVIRONMENTS", "Spend ceiling on concurrent managed environments."],
         ["OAUTH_ENABLED / OAUTH_ISSUER / OAUTH_AUDIENCE / OAUTH_JWKS_URI", "OIDC configuration for HTTP transport and the console."]],
        [3400, 5960], { mono: [0] }),

      // ── 9 VERIFICATION STATE ──
      new Paragraph({ children: [new PageBreak()] }),
      H1("9. Verification state as of 19 August 2026"),
      P("This section replaces the open-issues list carried by earlier drafts of this document. Every finding from the four-pass adversarial scan of 17 August has been fixed and re-verified, and the scan itself was superseded by two further passes that found three more defects. What follows is what has been measured, on what date, so a reader can judge how much weight the word \u0022clean\u0022 carries here."),
      H2("9.1 Open issues"),
      P("None known. That statement rests on the measurements in 9.3 rather than on an absence of reports, and it is worth reading with two caveats. First, the Capella v4 operations tagged [DOC] have never been confirmed against a live control plane and are deliberately not shipped - see 6.2. Second, a managed-backup restore path in the v4 reference is documented ambiguously enough that two readings disagree; the operation stays parked rather than shipping on a guess. Neither is a defect in this server, and both are recorded rather than resolved."),
      H2("9.2 Fixed since 17 August, and worth knowing about"),
      P("Three of these change what a client SEES, so they matter to anyone who integrated against an earlier build."),
      table(["Was", "Now"],
        [["Every refusal - unknown tool, scope denial, read-only mode, missing confirmation, spend ceiling, egress allowlist - was reported over the protocol as isError: false, i.e. as a successful tool call whose text happened to describe a failure.",
          "isError reflects the decision. A conversational caller read the text either way; a script, workflow step or UI branching on isError - the field the protocol defines for exactly that - saw success for a denied destructive operation."],
         ["The operator console hardcoded {\u0022ok\u0022: true} on every result, and its own code renders ok ? SUCCESS : ERROR - so a blocked exfiltration attempt painted a green SUCCESS badge and entered the run history as a success.",
          "ok is derived from the same classifier that writes the audit record, so the badge and the log cannot disagree."],
         ["serverInfo.version reported the version of the mcp LIBRARY, because the server was constructed without one and the SDK falls back to that. Clients displayed 1.27.0 or 1.29.0 depending on which library resolved.",
          "The server reports its own version from the installed distribution's metadata, so \u0022which build are you running?\u0022 has an answer over the protocol."]],
        [4680, 4680]),
      P("Also closed: the five HIGH findings and ten follow-ups from the 17 August scan, including the packaging omission that made the container and the wheel fail at startup, the dry-run preview that formatted caller-supplied passwords into unredacted prose, and the composite Capella ceiling guard the console answered differently from the transport. Two denial-of-service regressions of the same class were fixed with them: unbounded quantifiers before a fixed delimiter turned credential redaction into catastrophic backtracking, stalling the event loop for 36.9 and 54.7 seconds on a single crafted value. Both now complete in milliseconds."),
      H2("9.3 What has been measured"),
      table(["Check", "Result"],
        [["Test suite, randomised order and file order", "3075 passed, 1 skipped, both orders"],
         ["Coverage", "90.5 percent, gated at 89 percent in CI"],
         ["Mutation testing, three rounds", "218 mutations, all caught"],
         ["Lint and format", "ruff check and ruff format clean"],
         ["Functional, over real stdio", "Boots in both postures - 64 tools read-only, 134 in write mode; refusals flagged; dry run previews without executing; credentials masked in cb_mcp_status"],
         ["Packaging", "Wheel and container image both import from the INSTALLED copy, not the source tree"]],
        [3400, 5960]),
      P("Mutation testing is the check on the tests themselves: a control whose deliberate breakage no test notices has no test behind it, however green the suite looks. It is run in CI rather than by hand, because a suite verified once is a snapshot and not a guarantee."),
      H2("9.4 Confirmed clean"),
      P("Re-tested rather than inherited from the previous scan: SQL++ identifier escaping, including against embedded backticks, comment markers, statement chaining, NUL and fullwidth characters; command injection, of which there is none; path traversal, every REST segment being percent-encoded; TLS verification, weakened only under an explicit documented flag; mass assignment, every settings endpoint using an allow-list that refuses rather than drops; JWT validation; scope classification across all 208 tools; and retry idempotency, with no duplicate-billed-resource path found."),

      // ── 10 NEXT ──
      H1("10. Where to read next"),
      table(["Question", "Document"],
        [["How do I run it, what are the profiles and layers?", "README.md"],
         ["Operational procedures", "RUNBOOK.md"],
         ["Architecture, kept current with the code", "docs/ARCHITECTURE.md"],
         ["Portable, taggable datasets across clusters", "docs/FIXTURE_DESIGN.md"],
         ["Capella v4 operations written but not shipped, and why", "handlers/capella/spec_pending.py"],
         ["Contributing, tests, path-tagging conventions", "CONTRIBUTING.md"],
         ["Every configuration variable", ".env.example"]],
        [5200, 4160], { mono: [1] }),
    ],
  }],
});

Packer.toBuffer(doc).then(b => { fs.writeFileSync(OUT_DOCX, b);
  console.log("written", b.length, "bytes"); });
