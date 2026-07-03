#!/usr/bin/env python3
"""
Strip variant guards (BTC_ONLY, WEB3_VERSION, CYPHERPUNK_VERSION) from C source.
KOSMO = union of WEB3 and CYPHERPUNK, no BTC_ONLY.
Strategy: treat WEB3_VERSION and CYPHERPUNK_VERSION as always-defined,
           treat BTC_ONLY as never-defined.
"""
import os
import re
import sys

VARIANT_MACROS = {'BTC_ONLY', 'WEB3_VERSION', 'CYPHERPUNK_VERSION'}

def tokenize(line):
    """Split preprocessor condition into tokens for expression evaluation."""
    return re.sub(r'([()!])', r' \1 ', line).split()

def eval_condition(cond_str):
    """
    Evaluate a preprocessor condition under the KOSMO assumption.
    Returns True if the branch should be kept, False if removed, None if it needs both branches.
    We define: WEB3_VERSION=True, CYPHERPUNK_VERSION=True, BTC_ONLY=False
    """
    tokens = tokenize(cond_str)
    # Replace macros with boolean values
    processed = []
    for tok in tokens:
        if tok in VARIANT_MACROS:
            if tok == 'BTC_ONLY':
                processed.append('0')
            else:
                processed.append('1')
        elif tok == 'defined':
            continue  # handled by next token
        elif tok == '!':
            processed.append('not')
        elif tok == '&&':
            processed.append('and')
        elif tok == '||':
            processed.append('or')
        elif tok == '(' or tok == ')':
            processed.append(tok)
        else:
            processed.append(f'"{tok}"')
    expr = ' '.join(processed)
    try:
        return eval(expr)
    except:
        return None  # Can't evaluate, treat carefully

def process_file(filepath):
    """Process a single file, return (new_content, modifications_made, error)."""
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    result = []
    stack = []  # Stack of dicts tracking the guard state
    mods = 0
    skip_depth = 0  # If > 0, we're inside a block to be deleted
    
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Match preprocessing directives
        directive_match = re.match(r'#\s*(\w+)\s*(.*)', stripped)
        if directive_match:
            directive = directive_match.group(1)
            condition = directive_match.group(2).strip()
            
            if directive == 'ifdef':
                macro = condition.strip()
                is_variant = macro in VARIANT_MACROS
                
                if skip_depth > 0:
                    stack.append({'type': 'ifdef', 'macro': macro, 'skip': True})
                    skip_depth += 1
                elif not is_variant:
                    stack.append({'type': 'ifdef', 'macro': macro, 'skip': False})
                    result.append(line)
                elif macro == 'BTC_ONLY':
                    stack.append({'type': 'ifdef', 'macro': macro, 'skip': True})
                    skip_depth = 1
                    mods += 1
                else:  # WEB3_VERSION or CYPHERPUNK_VERSION — keep content, strip guard
                    stack.append({'type': 'ifdef', 'macro': macro, 'skip': False})
                    mods += 1
                    # Don't append the #ifdef line
                    
            elif directive == 'ifndef':
                macro = condition.strip()
                is_variant = macro in VARIANT_MACROS
                
                if skip_depth > 0:
                    stack.append({'type': 'ifndef', 'macro': macro, 'skip': True})
                    skip_depth += 1
                elif not is_variant:
                    stack.append({'type': 'ifndef', 'macro': macro, 'skip': False})
                    result.append(line)
                elif macro == 'BTC_ONLY':
                    # #ifndef BTC_ONLY is true in KOSMO — keep content, strip guard
                    stack.append({'type': 'ifndef', 'macro': macro, 'skip': False})
                    mods += 1
                else:  # WEB3_VERSION or CYPHERPUNK_VERSION — remove content
                    stack.append({'type': 'ifndef', 'macro': macro, 'skip': True})
                    skip_depth = 1
                    mods += 1
                    
            elif directive == 'if':
                if skip_depth > 0:
                    stack.append({'type': 'if', 'cond': condition, 'skip': True})
                    skip_depth += 1
                else:
                    val = eval_condition(condition)
                    if val is True:
                        # Condition true — keep content, strip directive
                        stack.append({'type': 'if', 'cond': condition, 'skip': False})
                        mods += 1
                    elif val is False:
                        # Condition false — skip content
                        stack.append({'type': 'if', 'cond': condition, 'skip': True})
                        skip_depth = 1
                        mods += 1
                    else:
                        # Can't determine — keep as-is for manual review
                        stack.append({'type': 'if', 'cond': condition, 'skip': False})
                        result.append(line)
                        
            elif directive == 'elif':
                if not stack:
                    result.append(line)
                else:
                    top = stack[-1]
                    if skip_depth > 0 and top.get('skip'):
                        # Previous block was skipping — check if THIS branch should be taken
                        val = eval_condition(condition)
                        if val is True:
                            top['skip'] = False
                            skip_depth -= 1
                            mods += 1
                        elif val is False:
                            mods += 1  # keep skipping
                        else:
                            result.append(line)
                    elif skip_depth > 0:
                        # Nested skip
                        skip_depth += 1
                        stack.append({'type': 'elif', 'cond': condition, 'skip': True})
                    else:
                        # We were keeping content — skip the rest of #if block
                        # Pop the if/elif stack frame and push a new skip frame
                        skip_depth = 1
                        top['skip'] = True
                        mods += 1
                        
            elif directive == 'else':
                if not stack:
                    result.append(line)
                else:
                    top = stack[-1]
                    if skip_depth > 0:
                        top['skip'] = not top.get('skip', False)
                        if not top['skip']:
                            skip_depth -= 1
                        mods += 1
                    else:
                        # From keeping to skipping
                        top['skip'] = True
                        skip_depth = 1
                        mods += 1
                        
            elif directive == 'endif':
                if not stack:
                    result.append(line)
                else:
                    top = stack.pop()
                    if top.get('skip') and skip_depth > 0:
                        skip_depth -= 1
                    elif not top.get('skip'):
                        pass  # just end the non-skipped block
                    mods += 1
            else:
                # Other directives (#include, #define, #pragma, etc.)
                if skip_depth > 0:
                    pass  # skip
                else:
                    result.append(line)
        else:
            # Non-directive line
            if skip_depth > 0:
                pass  # skip this line (content inside #if)
            else:
                result.append(line)
        i += 1
    
    return ''.join(result), mods, None

def main():
    # Process files in src/ui and src/crypto, excluding btc_only/cypherpunk/web3 dirs
    dirs_to_process = ['src/ui', 'src/crypto']
    skip_dirs = {'btc_only', 'cypherpunk', 'web3'}
    
    files = []
    for base_dir in dirs_to_process:
        for root, dirs, filenames in os.walk(base_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for f in filenames:
                if f.endswith(('.c', '.h')):
                    files.append(os.path.join(root, f))
    
    total_mods = 0
    processed = 0
    errors = []
    
    for filepath in files:
        try:
            new_content, mods, err = process_file(filepath)
            if err:
                errors.append(f"{filepath}: {err}")
                continue
            if mods > 0:
                with open(filepath, 'w') as f:
                    f.write(new_content)
                total_mods += mods
                processed += 1
                print(f"  ✓ {filepath}: {mods} guards stripped")
        except Exception as e:
            errors.append(f"{filepath}: {str(e)}")
    
    print(f"\n=== Summary ===")
    print(f"Files processed: {processed}")
    print(f"Total guards stripped: {total_mods}")
    if errors:
        print(f"Errors ({len(errors)}):")
        for e in errors:
            print(f"  ✗ {e}")

if __name__ == '__main__':
    main()
