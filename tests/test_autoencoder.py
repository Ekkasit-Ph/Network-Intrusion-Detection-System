import torch

from source.model.autoencoder import Autoencoder


def test_forward_shapes_roundtrip():
    model = Autoencoder(input_dim=39, latent_dim=8, hidden_dims=[32, 16], dropout=0.1)
    x = torch.randn(5, 39)
    x_hat, z = model(x)
    assert x_hat.shape == (5, 39)
    assert z.shape == (5, 8)


def test_no_hidden_dims_still_works():
    model = Autoencoder(input_dim=10, latent_dim=3, hidden_dims=[])
    x = torch.randn(4, 10)
    x_hat, z = model(x)
    assert x_hat.shape == (4, 10)
    assert z.shape == (4, 3)


def test_config_roundtrip():
    model = Autoencoder(input_dim=39, latent_dim=16, hidden_dims=[32], dropout=0.2)
    cfg = model.config()
    rebuilt = Autoencoder.from_config(cfg)
    assert rebuilt.config() == cfg
