# Virtual Compiler Is All You Need For Assembly Code Search

## Introduction

This repo contains the models and the corresponding evaluation datasets of ACL 2024 paper "Virtual Compiler Is All You Need For Assembly Code Search".

A virtual compiler is a LLM that is capable of compiling any programming language into underlying assembly code. The virtual compiler model is available at [elsagranger/VirtualCompiler](https://huggingface.co/elsagranger/VirtualCompiler), based on 34B CodeLlama.

We evaluate the similiarity of the virtual assembly code generated by the virtual compiler and the real assembly code using force execution by script [force-exec.py](./force_exec.py), the corresponding evaluation dataset is avaiable at [virtual_assembly_and_ground_truth](./virtual_assembly_and_ground_truth).

We evaluate the effective of the virtual compiler throught downstream task -- assembly code search, the evaluation dataset is avaiable at [elsagranger/AssemblyCodeSearch](https://huggingface.co/datasets/elsagranger/AssemblyCodeSearch).

## Usage

We use FastChat and vllm worker to host the model. Run these following commands in seperate terminals, such as `tmux`.

```shell
LOGDIR="" python3 -m fastchat.serve.openai_api_server \
    --host 0.0.0.0 --port 8080 \
    --controller-address http://localhost:21000

LOGDIR="" python3 -m fastchat.serve.controller \
    --host 0.0.0.0 --port 21000

LOGDIR="" RAY_LOG_TO_STDERR=1 \
    python3 -m fastchat.serve.vllm_worker \
    --model-path ./VirtualCompiler \
    --num-gpus 8 \
    --controller http://localhost:21000 \
    --max-num-batched-tokens 40960 \
    --disable-log-requests \
    --host 0.0.0.0 --port 22000 \
    --worker-address http://localhost:22000 \
    --model-names "VirtualCompiler"
```

Then with the model hosted, use `do_request.py` to make request to the model.

```shell
~/C/VirtualCompiler (main)> python3 do_request.py
test rdx, rdx
setz al
movzx eax, al
neg eax
retn
```