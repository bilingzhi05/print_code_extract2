from __future__ import annotations

import csv
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from utils.agent import ImpAgent
from utils.logger import log
from utils.token_splitter import TokenSplitter

try:
    from utils.config import LLM_CTX_NUM
except Exception:
    LLM_CTX_NUM = 2048


# =========================
# 说明：
# 1) 本文件提供“批量识别无分析价值日志”的工具函数。
# 2) 通过调用 ImpAgent(AgentBase) 将日志分成 10 类，并输出 CSV。
# 3) 使用 TokenSplitter 做分批，避免 prompt 超过大模型上下文。
# =========================


def _read_non_empty_lines(log_path: str) -> List[Tuple[int, str]]:
    """读取日志文件，返回 [(行号从1开始, 原始行文本), ...]，自动跳过空行。"""
    rows: List[Tuple[int, str]] = []
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f, start=1):
            text = (line or "").rstrip("\n")
            if not text.strip():
                continue
            rows.append((idx, text))
    return rows


def _json_loads_best_effort(text: str) -> Optional[Any]:
    """尽最大努力从模型输出中解析 JSON。"""
    if not text:
        return None
    raw = text.strip()
    try:
        return json.loads(raw)
    except Exception:
        pass
    # 兜底：截取第一个 JSON 数组或对象
    m = re.search(r"(\[[\s\S]*\]|\{[\s\S]*\})", raw)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
        return None


def _repair_json_with_llm(agent: ImpAgent, bad_text: str) -> Optional[Any]:
    """
    当 JSON 解析失败时，二次调用 LLM 进行 JSON 修复。
    只允许输出严格 JSON（数组或对象），不允许多余解释。
    """
    prompt = f"""
你是 JSON 修复器。请把下面内容修复为严格可解析的 JSON。
要求：
- 只输出 JSON（不要 markdown，不要解释）
- 保留原字段语义，不要丢项

待修复内容：
{bad_text}
"""
    fixed = agent.run(prompt) or ""
    return _json_loads_best_effort(fixed)


def _build_classification_prompt(items: List[Dict[str, Any]]) -> str:
    """
    构造分类 prompt。items 形如：
    [{"line_no": 12, "log": "xxx"}, ...]
    """
    # 分类定义（严格对齐用户的 10 类）
    # 注意：这里用中文解释，便于模型理解并给出稳定的分类。
    category_def = """
请将每条日志归类到以下 10 个类型之一（category_id 为 1~10）：
1. 完全无语义 / 纯占位 / 垃圾日志（必须剔除）
2. 只有 %s/%d/%p 等占位符，没有任何语义（必须剔除）
3. 框架/引用计数/RefBase/epoll/looper 调试（不是业务错误）
4. 事件通知，不是错误（必须剔除）
5. started already / 状态提示（不是错误）
6. Unknown/Invalid/Unsupported 但没有上下文（无分析价值）
7. dump / 文件操作 / 调试辅助（非错误）
8. 过于底层的 buffer/parcel/嵌套提示（框架保护，不是问题）
9. 正常的错误 log（有明确错误语义/上下文，值得分析）
10. 其他（无法判断或混合情况）
"""

    schema = """
必须仅输出 JSON 数组，数组长度必须与输入 items 长度一致，每项字段：
- "line_no": 输入的行号（整数）
- "category_id": 1~10
- "category_name": 类型中文名称（与上面对应）
- "reason": 简要原因（1~2句）
"""

    return f"""
你是日志语义筛选助手。请对输入日志进行分类，目的是识别“无分析价值/不支持”的日志类型。
{category_def}
{schema}

输入 items（JSON）：
{json.dumps(items, ensure_ascii=False)}
"""


def _batch_items_by_token(
    splitter: TokenSplitter,
    items: List[Dict[str, Any]],
    max_tokens: int,
) -> List[List[Dict[str, Any]]]:
    """
    使用 TokenSplitter 估算 token，按 max_tokens 分批，避免 prompt 超长。
    说明：这里采用“增量拼接 + 估算 prompt token”的简单策略，便于维护。
    """
    batches: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    # 固定开销：分类说明等（粗略估计）
    base_prompt_overhead = 600

    for it in items:
        candidate = current + [it]
        prompt = _build_classification_prompt(candidate)
        token_count = base_prompt_overhead + splitter.tokenize(prompt)
        if current and token_count > max_tokens:
            batches.append(current)
            current = [it]
        else:
            current = candidate

    if current:
        batches.append(current)
    return batches


def classify_logs_to_unsupport_csv(
    log_paths: List[str],
    output_name: str = "unsupport_log.csv",
) -> Dict[str, Any]:
    """
    批量调用大模型对日志做“无分析价值识别”，并输出 CSV 到每个日志文件所在目录。

    输入：
    - log_paths：一组日志文件路径（例如 *_extracted_contents.txt）

    输出：
    - 每个日志文件所在目录生成：unsupport_log.csv
      字段：line_no, log, category_id, category_name, reason
    - 返回汇总 dict，便于上层脚本打印/统计
    """
    agent = ImpAgent()
    # 重要：TokenSplitter 默认会走外部 tokenizer API，容易不可用且内部有递归风险
    # 这里显式关闭 tokenizer_url，使用 regex tokenize 估算，保证稳定可用
    splitter = TokenSplitter(max_tokens=3072, overlap=0, tokenizer_url="")

    # 为安全留出余量，避免贴近上下文上限导致模型截断
    ctx_budget = int(max(1024, min(LLM_CTX_NUM * 0.7, LLM_CTX_NUM - 512))) if isinstance(LLM_CTX_NUM, int) else 2048

    results: List[Dict[str, Any]] = []
    for path in log_paths:
        one_path = str(path).strip()
        if not one_path:
            continue
        if not os.path.exists(one_path):
            results.append({"log_path": one_path, "ok": False, "error": "file_not_found"})
            continue

        lines = _read_non_empty_lines(one_path)
        items = [{"line_no": ln, "log": text} for ln, text in lines]
        batches = _batch_items_by_token(splitter=splitter, items=items, max_tokens=ctx_budget)
        log(f"[identify_log_unsupport] {os.path.basename(one_path)}: total_items={len(items)}, batches={len(batches)}, ctx_budget={ctx_budget}")

        merged_rows: Dict[int, Dict[str, Any]] = {}

        for bi, batch in enumerate(batches, start=1):
            prompt = _build_classification_prompt(batch)
            resp = agent.run(prompt) or ""
            parsed = _json_loads_best_effort(resp)
            if parsed is None:
                parsed = _repair_json_with_llm(agent, resp)
            if not isinstance(parsed, list):
                # 批次失败：写入失败原因，避免静默丢失
                for it in batch:
                    ln = int(it["line_no"])
                    merged_rows[ln] = {
                        "line_no": ln,
                        "log": it.get("log", ""),
                        "category_id": 10,
                        "category_name": "其他",
                        "reason": f"JSON解析失败(批次{bi})",
                    }
                continue

            # 合并：以 line_no 为主键
            for row in parsed:
                if not isinstance(row, dict):
                    continue
                try:
                    ln = int(row.get("line_no"))
                except Exception:
                    continue
                merged_rows[ln] = {
                    "line_no": ln,
                    "log": next((t for l, t in lines if l == ln), ""),
                    "category_id": int(row.get("category_id", 10)) if str(row.get("category_id", "")).isdigit() else 10,
                    "category_name": str(row.get("category_name", "其他")).strip() or "其他",
                    "reason": str(row.get("reason", "")).strip(),
                }

        # 输出 CSV 到日志文件父目录
        out_dir = os.path.dirname(os.path.abspath(one_path))
        out_path = os.path.join(out_dir, output_name)
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["line_no", "log", "category_id", "category_name", "reason"],
            )
            writer.writeheader()
            for ln in sorted(merged_rows.keys()):
                writer.writerow(merged_rows[ln])

        results.append(
            {
                "log_path": one_path,
                "ok": True,
                "output_csv": out_path,
                "total": len(items),
                "batches": len(batches),
            }
        )

    return {"total_files": len(log_paths), "results": results}
