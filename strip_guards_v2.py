#!/usr/bin/env python3
"""
KOSMO guard stripper - removes BTC_ONLY, WEB3_VERSION, CYPHERPUNK_VERSION guards.
KOSMO = WEB3 | CYPHERPUNK (both defined), BTC_ONLY not defined.
"""
import os
import re

VARIANT_RE = re.compile(r'\b(BTC_ONLY|WEB3_VERSION|CYPHERPUNK_VERSION)\b')

def is_variant(line):
    return bool(VARIANT_RE.search(line))

def find_macro(line):
    """Extract the macro name from #ifdef or #ifndef line."""
    m = re.match(r'#\s*ifdef\s+(\w+)', line)
    if m:
        return m.group(1)
    m = re.match(r'#\s*ifndef\s+(\w+)', line)
    if m:
        return m.group(1)
    return None

def eval_if(expr):
    """Evaluate #if condition. Returns True/False/None."""
    s = expr
    # Replace variant macros
    s = re.sub(r'\bBTC_ONLY\b', '0', s)
    s = re.sub(r'\bWEB3_VERSION\b', '1', s)
    s = re.sub(r'\bCYPHERPUNK_VERSION\b', '1', s)
    # Replace defined(x) with 1
    s = re.sub(r'defined\s*\(\s*\w+\s*\)', '1', s)
    # Replace remaining macros with 1
    s = re.sub(r'\b[A-Z_][A-Z_0-9]*\b', '1', s)
    # Python syntax
    s = s.replace('!', ' not ')
    s = s.replace('&&', ' and ')
    s = s.replace('||', ' or ')
    try:
        return bool(eval(s))
    except:
        return None

def strip(path):
    with open(path) as f:
        lines = f.read().split('\n')
    
    out = []
    # Stack of (variant_macro_or_None, should_skip)
    # variant_macro_or_None: None means non-variant (include guard)
    # should_skip: True if we're currently skipping content
    stack = []
    mods = 0
    
    for line in lines:
        s = line.strip()
        
        # Check if it's a preprocessor directive
        m = re.match(r'#\s*(\w+)(.*)', s)
        if not m:
            # Regular code — emit only if not skipping
            if not stack or not stack[-1][1]:
                out.append(line)
            continue
        
        directive = m.group(1)
        rest = m.group(2).strip()
        
        if directive in ('ifdef', 'ifndef'):
            macro = rest.split()[0] if rest else ''
            is_var = macro in ('BTC_ONLY', 'WEB3_VERSION', 'CYPHERPUNK_VERSION')
            
            if is_var:
                mods += 1
                if macro == 'BTC_ONLY':
                    if directive == 'ifdef':
                        stack.append((macro, True))   # FALSE → skip
                    else:
                        stack.append((macro, False))  # TRUE → keep
                else:  # WEB3 or CYPHERPUNK
                    if directive == 'ifdef':
                        stack.append((macro, False))  # TRUE → keep
                    else:
                        stack.append((macro, True))   # FALSE → skip
                # Don't emit variant directive
            else:
                # Non-variant (include guard etc.) — always keep, assume active
                stack.append((None, False))
                out.append(line)
        
        elif directive == 'if':
            ivar = is_variant(s)
            if ivar:
                mods += 1
                val = eval_if(rest)
                if val is True:
                    stack.append((None, False))
                elif val is False:
                    stack.append((None, True))
                else:
                    stack.append((None, False))
                    out.append(line)
            else:
                stack.append((None, False))
                out.append(line)
        
        elif directive == 'elif':
            if not stack:
                out.append(line)
                continue
            top_macro, top_skip = stack[-1]
            if top_macro is not None:
                # Variant elif
                mods += 1
                val = eval_if(rest)
                if val is True:
                    stack[-1] = (top_macro, False)
                elif val is False:
                    stack[-1] = (top_macro, True)
                # else: keep previous state
            else:
                out.append(line)
        
        elif directive == 'else':
            if not stack:
                out.append(line)
                continue
            top_macro, top_skip = stack[-1]
            if top_macro is not None:
                mods += 1
                stack[-1] = (top_macro, not top_skip)
            else:
                out.append(line)
        
        elif directive == 'endif':
            if not stack:
                out.append(line)
                continue
            top_macro, _ = stack.pop()
            if top_macro is not None:
                mods += 1
                # Don't emit variant #endif
            else:
                out.append(line)
        
        else:
            # Other directives — keep as-is
            out.append(line)
    
    return '\n'.join(out), mods

def main():
    targets = []
    for base in ['src/ui', 'src/crypto']:
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in ('btc_only', 'cypherpunk', 'web3')]
            for f in files:
                if f.endswith(('.c', '.h')):
                    p = os.path.join(root, f)
                    with open(p) as fh:
                        if VARIANT_RE.search(fh.read()):
                            targets.append(p)
    
    print(f"Scanning {len(targets)} files...")
    total = 0
    for p in targets:
        new, n = strip(p)
        if n > 0:
            with open(p, 'w') as f:
                f.write(new)
            total += n
            print(f"  {p}: {n}")
    print(f"Done: {total} guards stripped")

if __name__ == '__main__':
    main()
