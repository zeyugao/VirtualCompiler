import requests
import random

CL = ['clang-11', 'clang-12', 'clang-9', 'gcc-11', 'gcc-7', 'gcc-9']
OP = ['O0', 'O1', 'O2', 'O3', 'Os']
ST = ['stripped', 'unstripped']


def process(source_code):
    compiler = random.choice(CL)
    optimizer = random.choice(OP)
    strip_type = random.choice(ST)
    prompt = f'Please compile this source code using {compiler} with optimization level {optimizer} into assembly code.'
    if strip_type == 'stripped':
        prompt += ' Strip the assembly code.'
    else:
        prompt += ' No strip the assembly code.'
    query_prompt = "<s>system\n" + prompt + \
        "</s>\n<s>user\n" + source_code + "</s>\n<s>assistant\n"
    return query_prompt, compiler, optimizer, strip_type


def do_request(src):
    url = "http://localhost:8080/v1/completions"

    query_prompt, _, _, _ = process(src)

    model_name = "VirtualCompiler"

    ret = requests.post(url, json={
        "prompt": query_prompt,
        "max_tokens": 4096,
        "temperature": 0.3,
        "stop": ["</s>"],
        "model": model_name,
        "echo": False,
        "logprobs": True,
    })

    return ret.json()


src = '''static int
layout_append(struct layout_cell *lc, char *buf, size_t len)
{
    if (len == 0)
        return (-1);

    return (0);
}
'''

ret = do_request(src)

print(ret['choices'][0]['text'])
