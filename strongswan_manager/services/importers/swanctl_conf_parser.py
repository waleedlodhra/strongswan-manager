"""
Parser for the modern /etc/swanctl/swanctl.conf format.

The format is a strongSwan-specific UCL-like syntax:
  section_name {         # named section (creates dict)
      key = value        # simple scalar assignment
      key = v1, v2       # comma-separated → list
      key = "quoted"     # quoted string
      subsection {       # nested named section
          ...
      }
  }
  # comments
  include glob_pattern   # file inclusion (relative to current dir)

Returns a nested dict tree matching the config structure.

Top-level sections produced:
  result["connections"]  → dict of conn_name → {version, local_addrs, ...}
  result["secrets"]      → dict of secret_key → {type, secret, id1, ...}
  result["pools"]        → dict of pool_name → {addrs, ...}
  result["authorities"]  → dict of auth_name → {cacert, crl_uris, ...}
"""
import glob
import os
import re


class SwanctlConfParser:
    """
    Parse a swanctl.conf file (and any conf.d/*.conf includes).

    Usage:
        tree = SwanctlConfParser.parse_file("/etc/swanctl/swanctl.conf")
        conns = tree.get("connections", {})
    """

    @classmethod
    def parse_file(cls, path: str) -> dict:
        try:
            with open(path) as f:
                text = f.read()
        except OSError:
            return {}
        return cls.parse_text(text, base_dir=os.path.dirname(os.path.abspath(path)))

    @classmethod
    def parse_text(cls, text: str, base_dir: str = "") -> dict:
        tokens = cls._tokenize(text, base_dir)
        parser = _TokenParser(tokens)
        return parser.parse_block()

    # ─── Tokeniser ────────────────────────────────────────────────────────────

    @classmethod
    def _tokenize(cls, text: str, base_dir: str) -> list[str]:
        """
        Expand includes then tokenise into: identifiers, { } = , and quoted strings.
        """
        expanded = cls._expand_includes(text, base_dir)
        tokens: list[str] = []
        i = 0
        while i < len(expanded):
            c = expanded[i]
            # Skip whitespace
            if c in " \t\r\n":
                i += 1
            # Comment to end of line
            elif c == "#":
                while i < len(expanded) and expanded[i] != "\n":
                    i += 1
            # Quoted string
            elif c in ('"', "'"):
                quote = c
                j = i + 1
                buf = []
                while j < len(expanded):
                    if expanded[j] == "\\" and j + 1 < len(expanded):
                        buf.append(expanded[j + 1])
                        j += 2
                    elif expanded[j] == quote:
                        j += 1
                        break
                    else:
                        buf.append(expanded[j])
                        j += 1
                tokens.append("".join(buf))
                i = j
            # Structural chars
            elif c in "{}=,":
                tokens.append(c)
                i += 1
            # Identifier / unquoted value
            else:
                j = i
                while j < len(expanded) and expanded[j] not in " \t\r\n{}=,#\"'":
                    j += 1
                tokens.append(expanded[i:j])
                i = j
        return tokens

    @classmethod
    def _expand_includes(cls, text: str, base_dir: str) -> str:
        result_lines = []
        for line in text.splitlines(keepends=True):
            stripped = line.strip()
            if stripped.startswith("include "):
                pattern = stripped[8:].strip()
                if not os.path.isabs(pattern) and base_dir:
                    pattern = os.path.join(base_dir, pattern)
                for path in sorted(glob.glob(pattern)):
                    try:
                        with open(path) as f:
                            included = f.read()
                        result_lines.append(
                            cls._expand_includes(included, os.path.dirname(path))
                        )
                    except OSError:
                        pass
            else:
                result_lines.append(line)
        return "".join(result_lines)


class _TokenParser:
    """Recursive descent parser that converts a token list into a nested dict."""

    def __init__(self, tokens: list[str]):
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _consume(self) -> str:
        t = self._tokens[self._pos]
        self._pos += 1
        return t

    def parse_block(self) -> dict:
        """
        Parse key=value assignments and named sub-sections until } or EOF.
        Returns a dict.  Sub-section keys whose names are NOT unique (e.g.
        multiple local{} inside the same connection) are merged.
        """
        result: dict = {}

        while self._peek() not in (None, "}"):
            name = self._consume()
            if name in ("{", "}", "=", ","):
                continue  # skip stray punctuation

            next_tok = self._peek()

            if next_tok == "=":
                # key = value  or  key = v1, v2, v3
                self._consume()  # consume =
                value = self._parse_value()
                result[name] = value

            elif next_tok == "{":
                # named sub-section: name { ... }
                self._consume()  # consume {
                sub = self.parse_block()
                if self._peek() == "}":
                    self._consume()  # consume }

                # Multiple sub-sections with same name (e.g. two local{} rounds)
                # are stored as a list of dicts
                if name in result:
                    existing = result[name]
                    if isinstance(existing, list):
                        existing.append(sub)
                    else:
                        result[name] = [existing, sub]
                else:
                    result[name] = sub

            else:
                # Bare name with no = or { — skip
                pass

        return result

    def _parse_value(self) -> str | list[str]:
        """
        Parse a scalar or comma-separated list.
        Returns a str if single value, list[str] if comma-separated.
        """
        values = []
        # Collect first value
        tok = self._peek()
        if tok is not None and tok not in ("{", "}", "=", ","):
            values.append(self._consume())
        # Collect additional comma-separated values
        while self._peek() == ",":
            self._consume()  # consume ","
            tok = self._peek()
            if tok is not None and tok not in ("{", "}", "=", ","):
                values.append(self._consume())

        if len(values) == 1:
            return values[0]
        return values if values else ""
