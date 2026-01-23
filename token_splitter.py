import re
import requests
import json
from logger import log

class TokenSplitter:
    def __init__(self, max_tokens=2048, overlap=50, tokenizer_url="http://10.58.11.60:1234/tokenize"):
        self.max_tokens = max_tokens
        self.overlap = overlap
        self.tokenizer_url = tokenizer_url  # e.g., "http://10.58.11.60:1234/tokenize"

    def tokenize_regex(self, text):
        """
        Simple regex-based tokenizer.
        Matches words, numbers, punctuation, whitespace.
        """
        # This regex matches:
        # 1. Words/identifiers: \w+
        # 2. Non-whitespace symbols: [^\w\s]+
        # 3. Newlines/Whitespace: \s+
        # We generally treat whitespace as separate tokens or ignore them depending on the model.
        # For safety, let's include everything so we can reconstruct exactly.
        if self.tokenizer_url:
            ret = self.tokenize_api(text)
            # print(ret)
            return ret
        ret = re.findall(r'\w+|[^\w\s]+|\s+', text)
        print(ret, len(ret))
        return len(ret)

    def tokenize_api(self, text):
        """
        Uses an external API to tokenize text.
        """
        if not self.tokenizer_url:
            return len(self.tokenize_regex(text))

        try:
            payload = {
                "text": text,
                "include_special_tokens": False
            }
            headers = {"Content-Type": "application/json"}
            response = requests.post(self.tokenizer_url, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                # Assuming the API returns a list of token IDs in "tokens"
                # print(f"API response: {result}")
                if "token_count" in result:
                    return result["token_count"]
                # Some APIs might return "count" directly?
                return 0
            else:
                print(f"Error calling tokenizer API: {response.status_code}")
                return len(self.tokenize_regex(text))
        except Exception as e:
            print(f"Exception calling tokenizer API: {e}")
            return len(self.tokenize_regex(text))

    def tokenize(self, text):
        return self.tokenize_regex(text)


    def split_text(self, text):
        """
        Splits text into chunks if it exceeds max_tokens.
        Returns a list of chunks (strings).
        """
        # 如果总长度小于 max_tokens，直接返回
        total_tokens = self.tokenize(text)
        if total_tokens <= self.max_tokens:
            return [text]
        
        chunks = []
        current_chunk = []
        current_length = 0
        
        # 按行分割，避免切断一行代码
        lines = text.split('\n')
        
        for line in lines:
            line_with_newline = line + '\n'
            line_tokens = self.tokenize(line_with_newline)
            
            # 如果单行就超过了 max_tokens（极少情况），强制切分或者直接放入（目前策略：单独放入，可能会被截断）
            if line_tokens > self.max_tokens:
                # 如果当前块不为空，先保存当前块
                if current_chunk:
                    chunks.append("".join(current_chunk))
                    current_chunk = []
                    current_length = 0
                
                # 将超长行作为一个单独的块（或者可以考虑按字符强行切分，这里暂时保持完整性）
                chunks.append(line_with_newline)
                continue

            # 如果加入当前行会超过 max_tokens，则保存当前块，开启新块
            if current_length + line_tokens > self.max_tokens:
                chunks.append("".join(current_chunk))
                
                # 计算重叠部分（Overlap）
                # 回溯之前的行，直到达到 overlap 大小
                overlap_chunk = []
                overlap_len = 0
                # 从当前块的末尾向前遍历
                for prev_line in reversed(current_chunk):
                    prev_len = self.tokenize(prev_line)
                    if overlap_len + prev_len > self.overlap:
                        break
                    overlap_chunk.insert(0, prev_line)
                    overlap_len += prev_len
                
                current_chunk = overlap_chunk + [line_with_newline]
                current_length = overlap_len + line_tokens
            else:
                current_chunk.append(line_with_newline)
                current_length += line_tokens
        
        # 处理最后一个块
        if current_chunk:
            chunks.append("".join(current_chunk))
            
        return chunks
            # e.g. start=0, max=100, overlap=50 -> end=100. next_start=50.
            # e.g. start=50, max=100 -> end=150. next_start=100.
            # Correct.


if __name__ == "__main__":
    import sys
    
    # Simple test
    if len(sys.argv) > 1:
        # If file provided
        with open(sys.argv[1], 'r') as f:
            content = f.read()
        splitter = TokenSplitter(max_tokens=3072, overlap=50)
        log( f"Original length: {splitter.tokenize(content)} tokens")
        chunks = splitter.split_text(content)
        for i, chunk in enumerate(chunks):
            log(f"Chunk {i+1} (tokens: {splitter.tokenize(chunk)})")
            # log(f"Chunk {i+1} content: {chunk}")
    else:
        # Dummy test
        text = """
        你是一个代码分析助手。请分析以下 C/C++ 代码片段，找出所有疑似表示错误、警告或失败情况的打印语句（如 printf, fprintf, ALOGE, LOG 等）。
请忽略普通的 info/debug 打印，除非它们看起来像错误（例如包含 "failed", "error", "timeout", "exception" 等关键词）。
请以有效的 JSON 列表格式返回结果。每个项目应包含：
- "line_content": 打印语句的完整代码（例如 `printf("Error %d", err);`）。如果代码片段中没有找到符合条件的打印语句，请将此字段设置为空字符串 ""。**重要：请保持原样输出字符串内容，绝对不要转义百分号（%）或其他格式化字符，也不要转义美元符号（$）。例如，输出 "%s" 而不是 "\\$s" 或 "\\%s"。**
- "line_number": 代码片段中的相对行号（从 1 开始计数）。

代码片段：
```c
{chunk}
```

仅输出 JSON 列表。不要使用 markdown 格式，不要包含任何解释。
如果未找到任何打印语句，请返回一个空列表 `[]`。
输出示例：
[
  {{"line_content": "printf(\"Connection failed\\n\");", "line_number": 5}},
  {{"line_content": "ALOGE(\"Timeout waiting for response: %d\", timeout_ms);", "line_number": 12}}
]
        """
        splitter = TokenSplitter(max_tokens=3072, overlap=50)
        toknes_len = splitter.tokenize(text)
        print(f"Dummy text split into chunks to {toknes_len} chunks.")
