import torch
import pandas as pd
from sklearn.model_selection import train_test_split

model = torch.load("models/model.pth")
data = pd.read_csv("training.csv")
