"""Model loading in the safe form (Phase 6 negative control).

safetensors carries no pickle payload to execute, and torch.load is called
with weights_only=True so the unpickler refuses anything that is not a plain
tensor. Neither call can run code from the file, so there is nothing to label.
"""
import torch
from safetensors.torch import load_file


def load_safetensors(path):
    return load_file(path)


def load_weights_only(path):
    return torch.load(path, weights_only=True)
