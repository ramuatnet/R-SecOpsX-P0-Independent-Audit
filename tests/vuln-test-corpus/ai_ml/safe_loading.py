"""The safe shape of the same two loads: any finding here is a false positive.

weights_only=True restricts torch.load to plain tensors and refuses pickle
globals; trust_remote_code is explicitly off, so the installed library's own
modeling code runs. (A .safetensors checkpoint would be safer still -- the
artifact layer checks that separately on binary files.)
"""
import torch
from transformers import AutoModel


def load_weights(path):
    return torch.load(path, weights_only=True)


def load_remote_model(name):
    return AutoModel.from_pretrained(name, trust_remote_code=False)
