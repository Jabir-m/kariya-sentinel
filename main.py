import os
import sys
import json
import asyncio
import datetime
import threading
from contextlib import AsyncExitStack
from typing import Dict, Any, List, Tuple, Optional
from openai import AsyncOpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Environment & Model Configuration
MODEL = os.environ.get("OLLAMA_MODEL", "gemma4:31b")
OLLAMA_API_KEY = os.environ.get(
    "OLLAMA_API_KEY",
    "4b5af9aeb43c4411b43f505b4e3e8b86.B-68PsDHIyQlrm0d0d9OmA9e"
)
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "https://ollama.com/v1")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_DIR = os.path.join(BASE_DIR, "servers", "src")
SESSION_FILE = os.path.join(BASE_DIR, "session_history.json")
MEMORY_FILE = os.path.join(BASE_DIR, "MEMORY.md")
HEARTBEAT_FILE = os.path.join(BASE_DIR, "HEARTBEAT.md")
DATASET_PATH = os.path.join(BASE_DIR, "kariya", "dataset.json")

# Kariya Pipeline & Store Integration
from kariya.pipeline import TriagePipeline
from kariya.offline_store import OfflineIncidentStore
from kariya.evaluator import evaluate_pipeline

triage_pipeline = TriagePipeline(DATASET_PATH)
offline_store = OfflineIncidentStore()

# Multi-MCP Server Registry (6 Subsystems)
MCP_SERVERS = {
    "terminal": {
        "command": sys.executable,
        "args": [os.path.join(SERVERS_DIR, "terminal", "terminal_server.py")],
        "description": "Host shell execution (bash commands) and system monitoring"
    },
    "websearch": {
        "command": sys.executable,
        "args": [os.path.join(SERVERS_DIR, "search", "search_server.py")],
        "description": "Real-time web search, live news, and URL text fetch (No login/sign-up required)"
    },
    "everything": {
        "command": "node",
        "args": [os.path.join(SERVERS_DIR, "everything", "dist", "index.js"), "stdio"],
        "description": "Protocol testing, deterministic arithmetic (get-sum), echo, and utilities"
    },
    "memory": {
        "command": "node",
        "args": [os.path.join(SERVERS_DIR, "memory", "dist", "index.js")],
        "description": "Knowledge graph long-term memory for user facts, habits, and relations"
    },
    "filesystem": {
        "command": "node",
        "args": [os.path.join(SERVERS_DIR, "filesystem", "dist", "index.js"), BASE_DIR],
        "description": "Secure workspace file operations, reading, editing, and directory listing"
    },
    "sequentialthinking": {
        "command": "node",
        "args": [os.path.join(SERVERS_DIR, "sequentialthinking", "dist", "index.js")],
        "description": "Dynamic multi-stage reflective reasoning and problem decomposition"
    }
}

client = AsyncOpenAI(
    base_url=OLLAMA_BASE_URL,
    api_key=OLLAMA_API_KEY
)

def format_mcp_result(result: Any) -> str:
    """Extract clean string text from MCP CallToolResult."""
    if not hasattr(result, "content") or not result.content:
        return "Operation succeeded with empty output."
        
    chunks = []
    for item in result.content:
        if hasattr(item, "text"):
            chunks.append(item.text)
        elif hasattr(item, "data"):
            chunks.append(f"[Binary data: {len(item.data)} bytes]")
        else:
            chunks.append(str(item))
            
    text = "\n".join(chunks)
    if getattr(result, "isError", False):
        return f"Error: {text}"
    return text

class KariyaAgent:
    """KARIYA AI: Sovereign Autonomous Cyber Defense & Triage Agent."""

    def __init__(self):
        self.sessions: Dict[str, ClientSession] = {}
        self.tool_routes: Dict[str, Tuple[str, ClientSession]] = {}
        self.openai_tools: List[Dict[str, Any]] = []
        self.tool_metadata: Dict[str, Dict[str, Any]] = {}
        self.messages: List[Dict[str, Any]] = []

    async def initialize(self, stack: AsyncExitStack):
        """Connect to all configured MCP servers and discover available tools."""
        print("🛡️  Initializing KARIYA AI Subsystems...")
        for name, config in MCP_SERVERS.items():
            script_path = config["args"][0]
            if not os.path.exists(script_path):
                print(f"  ⚠️  Subsystem '{name}' skipped (missing: {script_path})")
                continue

            try:
                params = StdioServerParameters(command=config["command"], args=config["args"])
                read_stream, write_stream = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
                await session.initialize()
                self.sessions[name] = session

                tools_resp = await session.list_tools()
                for tool in tools_resp.tools:
                    self.tool_routes[tool.name] = (name, session)
                    self.tool_metadata[tool.name] = {
                        "server": name,
                        "description": tool.description or "No description available"
                    }
                    self.openai_tools.append({
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description or "",
                            "parameters": tool.input_schema or {"type": "object", "properties": {}}
                        }
                    })
                print(f"  ✓ [{name}] online ({len(tools_resp.tools)} tools registered)")
            except Exception as e:
                print(f"  ❌ [{name}] failed to connect: {e}")

        self.load_session_or_reset()

    def build_system_prompt(self) -> str:
        """Construct a 3-tier system prompt: Stable Identity -> Context Snapshot -> Volatile Knowledge."""
        soul_content = "You are KARIYA Sentinel, a sovereign cyber incident triage defense engine developed by Builder OS."
        soul_path = os.path.join(BASE_DIR, "soul.md")
        if os.path.exists(soul_path):
            with open(soul_path, "r", encoding="utf-8") as f:
                soul_content = f.read().strip()

        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        tier2_context = (
            f"# Environment Context Snapshot\n"
            f"- Current Date/Time: {now_utc}\n"
            f"- Workspace Root: {BASE_DIR}\n"
            f"- Core LLM: {MODEL}\n"
            f"- Active MCP Subsystems: {', '.join(self.sessions.keys())}\n"
            f"- Total Tools Registered: {len(self.openai_tools)}"
        )

        volatile_parts = []
        skill_path = os.path.join(BASE_DIR, "skill.md")
        if os.path.exists(skill_path):
            with open(skill_path, "r", encoding="utf-8") as f:
                volatile_parts.append(f.read().strip())

        if os.path.exists(MEMORY_FILE):
            with open(MEMORY_FILE, "r", encoding="utf-8") as f:
                volatile_parts.append(f"# Persistent Memory Snapshot (MEMORY.md)\n{f.read().strip()}")

        volatile_section = "\n\n---\n".join(volatile_parts)
        return f"{soul_content}\n\n---\n{tier2_context}\n\n---\n{volatile_section}"

    def load_session_or_reset(self):
        """Restore conversation history from disk if available; otherwise reset."""
        system_prompt = self.build_system_prompt()
        if os.path.exists(SESSION_FILE):
            try:
                with open(SESSION_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list) and len(data) > 0:
                        self.messages = data
                        self.messages[0] = {"role": "system", "content": system_prompt}
                        print(f"  💾 Resumed prior session context ({len(self.messages) - 1} turns loaded)")
                        return
            except Exception:
                pass
        self.messages = [{"role": "system", "content": system_prompt}]

    def save_session(self):
        """Persist session history to disk."""
        try:
            serializable = []
            for m in self.messages:
                if isinstance(m, dict):
                    serializable.append(m)
                elif hasattr(m, "model_dump"):
                    serializable.append(m.model_dump())
                elif hasattr(m, "__dict__"):
                    serializable.append(m.__dict__)
            with open(SESSION_FILE, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️  Could not save session: {e}")

    def reset_conversation(self):
        """Clear conversation history and persist empty state."""
        system_prompt = self.build_system_prompt()
        self.messages = [{"role": "system", "content": system_prompt}]
        self.save_session()

    async def execute_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        """Route and execute an MCP tool with formatted feedback."""
        if name not in self.tool_routes:
            return f"Error: Tool '{name}' is not registered."

        server_name, session = self.tool_routes[name]
        print(f"\n⚙️  [MCP Action] [{server_name}] ➜ {name}")
        args_str = json.dumps(arguments, ensure_ascii=False)
        if len(args_str) > 120:
            args_str = args_str[:120] + "..."
        print(f"   Args: {args_str}")

        try:
            result = await session.call_tool(name, arguments)
            text = format_mcp_result(result)
            preview = text.strip().replace("\n", " ")
            if len(preview) > 140:
                preview = preview[:140] + "..."
            print(f"   Result: {preview}\n")
            return text
        except Exception as e:
            err = f"Error executing tool '{name}': {e}"
            print(f"   ❌ {err}\n")
            return err

    async def process_user_turn(self, user_text: str):
        """Autonomous execution loop with multi-turn tool calling."""
        self.messages.append({"role": "user", "content": user_text})
        max_turns = 12
        turn_count = 0

        while turn_count < max_turns:
            turn_count += 1
            try:
                response = await client.chat.completions.create(
                    model=MODEL,
                    messages=self.messages,
                    tools=self.openai_tools if self.openai_tools else None,
                    tool_choice="auto" if self.openai_tools else None
                )
            except Exception as e:
                print(f"\n❌ API Error: {e}\n")
                return

            choice = response.choices[0]
            msg = choice.message
            self.messages.append(msg)

            if msg.tool_calls:
                for tc in msg.tool_calls:
                    fn_name = tc.function.name
                    try:
                        fn_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                    except Exception:
                        fn_args = {}

                    tool_output = await self.execute_tool(fn_name, fn_args)
                    self.messages.append({
                        "tool_call_id": tc.id,
                        "role": "tool",
                        "name": fn_name,
                        "content": tool_output
                    })
            else:
                reply = msg.content or ""
                print(f"\nKARIYA: {reply}\n")
                break

        self.save_session()

    async def cli_triage(self, text: str):
        """Execute instant Track D incident triage from the CLI."""
        print("\n🔍 Running KARIYA Triage Pipeline...")
        res = triage_pipeline.process_report(text)
        is_off = offline_store.is_offline_mode()
        offline_store.save_incident(res, is_offline=is_off)

        print("=" * 60)
        print(f"  THREAT TYPE:     {res['incident_type']}")
        print(f"  SEVERITY (SLA):  {res['severity']} ({res['sla_level']} — {res['sla']})")
        print(f"  ROUTING TARGET:  {res['destination']}")
        print(f"  PII REDACTED:    {res['pii_count']} tokens masked (BVN/NIN/Phone/Names)")
        print(f"  IOCs EXTRACTED:  {res['ioc_count']} indicators ({', '.join(res['technical_details']['ips'] + res['technical_details']['domains']) or 'None'})")
        print("-" * 60)
        print("  DECISION RATIONALE:")
        print(f"  {res['type_rationale']}")
        print("-" * 60)
        print("  SANITIZED OUTPUT (SAFE FOR NG-CERT / REGULATORS):")
        print(f"  {res['cleaned_text']}")
        print("=" * 60 + "\n")

    def show_benchmark(self):
        """Display Track D evaluation results on the 360-report dataset."""
        ev = evaluate_pipeline(DATASET_PATH)
        s = ev["summary"]
        print("\n" + "=" * 60)
        print("  KARIYA SENTINEL — TRACK D GROUND TRUTH BENCHMARK")
        print("=" * 60)
        print(f"  Dataset Size:            {s['total_reports_evaluated']} Labeled Reports")
        print(f"  Type Accuracy:           {s['incident_type_accuracy']}%")
        print(f"  Severity Match:          {s['severity_accuracy']}%")
        print(f"  IOC Extraction Recall:   {s['ioc_extraction_recall']}%")
        print(f"  PII Redaction Rate:      {s['pii_redaction_rate']}%")
        print(f"  Noise Reduction (Dedup): {s['deduplication_reduction_percent']}%")
        print(f"  Master Incidents Formed: {s['master_clusters_formed']} (From {s['total_reports_evaluated']} Raw Alerts)")
        print("-" * 60)
        print("  CATEGORY BREAKDOWN (Precision / Recall / F1):")
        for m in ev["category_metrics"]:
            print(f"  • {m['category'][:32]:<32} P:{m['precision']:>5}% | R:{m['recall']:>5}% | F1:{m['f1_score']:>5}%")
        print("=" * 60 + "\n")

    def show_honest_errors(self):
        """Display Hackathon Rule 05 Honest Error Analysis."""
        ev = evaluate_pipeline(DATASET_PATH)
        errs = ev.get("honest_error_analysis", [])
        print("\n" + "=" * 60)
        print("  HACKATHON RULE 05: HONEST ERROR ANALYSIS (WHERE WE FAIL & WHY)")
        print("=" * 60)
        print("  Judges Reward Teams That Know Their Limits. Here Are Documented Edge Cases:\n")
        for i, err in enumerate(errs[:4], 1):
            print(f"[{i}] Report ID: {err['report_id']} ({err['organization']})")
            print(f"    True Threat: {err['true_type']}  |  Predicted: {err['predicted_type']}")
            print(f"    Snippet: \"{err['snippet']}\"")
            print(f"    Root Cause: {err['reason']}\n")
        print("=" * 60 + "\n")

    async def run_heartbeat(self):
        """Execute autonomous heartbeat audit based on standing instructions in HEARTBEAT.md."""
        heartbeat_instructions = ""
        if os.path.exists(HEARTBEAT_FILE):
            with open(HEARTBEAT_FILE, "r", encoding="utf-8") as f:
                heartbeat_instructions = f.read().strip()

        prompt = (
            f"[AUTONOMOUS HEARTBEAT ROUTINE TRIGGERED]\n"
            f"Please execute the standing checks specified in HEARTBEAT.md:\n\n"
            f"{heartbeat_instructions}\n\n"
            f"Audit the incident triage queue, check host status, and report HEARTBEAT_OK or HEARTBEAT_ALERT."
        )
        print("\n💓 Running KARIYA Autonomous Heartbeat Audit...")
        await self.process_user_turn(prompt)

    def print_tools(self):
        """List registered tools grouped by MCP server."""
        print("\n" + "=" * 50)
        print(f"  KARIYA REGISTERED TOOLS ({len(self.openai_tools)} Tools)")
        print("=" * 50)
        servers: Dict[str, List[str]] = {}
        for name, meta in self.tool_metadata.items():
            servers.setdefault(meta["server"], []).append(f"  • {name:26} - {meta['description']}")

        for s_name, tool_lines in sorted(servers.items()):
            print(f"\n[{s_name.upper()}] ({len(tool_lines)} tools):")
            for line in tool_lines:
                print(line)
        print("=" * 50 + "\n")

def start_web_server():
    """Launch the FastAPI / Tailwind web server in a separate background thread."""
    from kariya.web_server import run_server
    port = int(os.environ.get("PORT", "8080"))
    server_thread = threading.Thread(target=run_server, kwargs={"host": "0.0.0.0", "port": port}, daemon=True)
    server_thread.start()
    print(f"🌐 Web Dashboard live at: http://localhost:{port}")

async def main():
    if "--web" in sys.argv:
        port = int(os.environ.get("PORT", "8080"))
        print(f"🚀 Launching KARIYA Sentinel Web Platform on port {port}...")
        start_web_server()
        while True:
            await asyncio.sleep(3600)
        return

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   KARIYA SENTINEL — Sovereign National Cyber Triage SOAR    ║")
    print("║   Developed by Builder OS (ICSC 2026 Universities)           ║")
    print("║   Lead: Jabir Mustafa Sulaiman | Ahamad Musa | Halima Lawal  ║")
    print(f"║   Model: {MODEL:<18} Track: D (Government / PubSector)║")
    print("╚══════════════════════════════════════════════════════════════╝")

    agent = KariyaAgent()

    async with AsyncExitStack() as stack:
        await agent.initialize(stack)

        print("\nReady! Commands:")
        print("  /triage <report>  - Triage a messy incident report (English/Pidgin)")
        print("  /benchmark        - View 360-report evaluation metrics")
        print("  /errors           - View Rule 05 honest error analysis")
        print("  /web              - Launch modern Tailwind CSS web dashboard")
        print("  /heartbeat        - Run autonomous queue & host self-audit")
        print("  /bash <cmd>       - Direct terminal/shell execution")
        print("  /search <query>   - Live DuckDuckGo web search (no login/API key)")
        print("  /tools            - View all registered MCP tools")
        print("  /clear, /exit     - Clear session or save & quit\n")

        while True:
            try:
                user_input = await asyncio.to_thread(input, "You: ")
            except (KeyboardInterrupt, EOFError):
                print("\nKARIYA: Session saved. System standing guard.")
                agent.save_session()
                break

            cmd = user_input.strip()
            if not cmd:
                continue

            if cmd.lower() in ("/exit", "exit", "quit"):
                agent.save_session()
                print("KARIYA: Session saved. System standing guard.")
                break
            elif cmd.lower() in ("/clear", "clear"):
                agent.reset_conversation()
                print("KARIYA: Conversation memory reset.\n")
                continue
            elif cmd.lower() in ("/tools", "tools"):
                agent.print_tools()
                continue
            elif cmd.lower().startswith("/triage "):
                text = cmd[8:].strip()
                await agent.cli_triage(text)
                continue
            elif cmd.lower() in ("/benchmark", "benchmark"):
                agent.show_benchmark()
                continue
            elif cmd.lower() in ("/errors", "errors"):
                agent.show_honest_errors()
                continue
            elif cmd.lower() in ("/web", "web"):
                start_web_server()
                continue
            elif cmd.lower().startswith("/bash "):
                sh_cmd = cmd[6:].strip()
                server, session = agent.tool_routes.get("execute_command", (None, None))
                if session:
                    res = await session.call_tool("execute_command", {"command": sh_cmd})
                    print("\n" + format_mcp_result(res) + "\n")
                else:
                    print("Terminal tool not available.")
                continue
            elif cmd.lower().startswith("/search "):
                query = cmd[8:].strip()
                server, session = agent.tool_routes.get("web_search", (None, None))
                if session:
                    res = await session.call_tool("web_search", {"query": query, "max_results": 4})
                    print("\n" + format_mcp_result(res) + "\n")
                else:
                    print("Web search tool not available.")
                continue
            elif cmd.lower() in ("/heartbeat", "heartbeat"):
                await agent.run_heartbeat()
                continue
            elif cmd.lower() in ("/help", "help"):
                print("\nKARIYA Commands:")
                print("  /triage <text>   - Triage messy incident report")
                print("  /benchmark       - View Track D evaluation metrics")
                print("  /errors          - View Rule 05 honest error analysis")
                print("  /web             - Start Tailwind CSS web dashboard")
                print("  /heartbeat       - Run autonomous health & queue audit")
                print("  /bash <cmd>      - Direct shell execution")
                print("  /search <query>  - Live web search")
                print("  /tools           - List all 42 MCP tools")
                print("  /exit            - Save session and quit\n")
                continue

            await agent.process_user_turn(cmd)

if __name__ == "__main__":
    asyncio.run(main())
