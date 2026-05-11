terraform {
  required_providers {
    torii = {
      source = "toriigateorg/torii"
    }
  }
}

provider "torii" {
  endpoint  = "https://torii.example.com"
  api_token = var.torii_api_token
}

variable "torii_api_token" {
  type      = string
  sensitive = true
}
