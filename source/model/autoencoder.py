"""Autoencoder architecture (module 3).

Symmetric encoder/decoder MLP. No activation on the latent layer (it needs
to represent negative values freely) and no activation on the final
reconstruction layer (the target is standardized data, which is centered
around 0 and can be negative).
"""

from __future__ import annotations

import torch
from torch import nn


class Autoencoder(nn.Module):
    def __init__(
        self,
        input_dim: int,
        latent_dim: int,
        hidden_dims: list[int],
        dropout: float = 0.0,
    ) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.hidden_dims = list(hidden_dims)
        self.dropout = dropout

        encoder_layers: list[nn.Module] = []
        dims = [input_dim] + self.hidden_dims + [latent_dim]
        for i in range(len(dims) - 1):
            encoder_layers.append(nn.Linear(dims[i], dims[i + 1]))
            is_last = i == len(dims) - 2
            if not is_last:
                encoder_layers.append(nn.ReLU())
                if dropout > 0:
                    encoder_layers.append(nn.Dropout(dropout))
        self.encoder = nn.Sequential(*encoder_layers)

        decoder_layers: list[nn.Module] = []
        rev_dims = [latent_dim] + self.hidden_dims[::-1] + [input_dim]
        for i in range(len(rev_dims) - 1):
            decoder_layers.append(nn.Linear(rev_dims[i], rev_dims[i + 1]))
            if i < len(rev_dims) - 2:
                decoder_layers.append(nn.ReLU())
                if dropout > 0:
                    decoder_layers.append(nn.Dropout(dropout))
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        z = self.encoder(x)
        x_hat = self.decoder(z)
        return x_hat, z

    def config(self) -> dict:
        return {
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "hidden_dims": self.hidden_dims,
            "dropout": self.dropout,
        }

    @classmethod
    def from_config(cls, config: dict) -> "Autoencoder":
        return cls(
            input_dim=config["input_dim"],
            latent_dim=config["latent_dim"],
            hidden_dims=config["hidden_dims"],
            dropout=config.get("dropout", 0.0),
        )
