"""Model-loading patterns labelled by their own observable behaviour (Phase 6).

torch.load unpickles whatever file it is pointed at: that is CWE-502 whether
or any rule reports it. trust_remote_code=True executes the modeling code the
model repository ships instead of the installed library: that is CWE-94 from
an external control sphere. Both are labelled at the call site.
"""
import torch
from transformers import AutoConfig, AutoModel


def load_weights(path):
    # CWE-502: unpickling the checkpoint executes whatever the file says.
    return torch.load(path)


def load_remote_model(name):
    # CWE-94: modeling code from the repository is executed on load.
    config = AutoConfig.from_pretrained(name, trust_remote_code=True)
    return AutoModel.from_pretrained(name, config=config)
