import asyncio
import re
from pathlib import Path
from typing import List, Dict, Any


async def load_project_files(dir_path: str):
    files = []

    def walk(current_path: Path):
        for entry in current_path.iterdir():
            if entry.is_dir():
                if entry.name in ["node_modules", "dist", "build", ".git"]:
                    continue
                walk(entry)
            else:
                if re.search(r"\.(js|ts|jsx|tsx|html)$", entry.name, re.IGNORECASE):
                    content = entry.read_text(encoding="utf-8", errors="ignore")
                    print(f"[DEBUG] Loading file: {entry}")
                    files.append({
                        "path": str(entry),
                        "content": content,
                        "isServerCode": bool(
                            re.search(r"\.(js|ts)$", entry.name, re.IGNORECASE)
                            and re.search(r"(express|koa|fastify)", content)
                        ),
                        "isClientCode": bool(
                            re.search(r"\.(js|ts|jsx|tsx|html)$", entry.name, re.IGNORECASE)
                            and re.search(r"(document|window)", content)
                        ),
                        "language": entry.suffix.lstrip(".").lower(),
                        "size": len(content),
                    })

    # run the sync walker in a thread so it won’t block asyncio
    await asyncio.to_thread(walk, Path(dir_path))
    return files