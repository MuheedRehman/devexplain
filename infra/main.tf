terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "random_integer" "suffix" {
  min = 10000
  max = 99999
}

locals {
  app_name = "${var.app_name_prefix}-${random_integer.suffix.result}"
}

resource "azurerm_resource_group" "rg" {
  name     = "${local.app_name}-rg"
  location = var.location
}

resource "azurerm_service_plan" "plan" {
  name                = "${local.app_name}-plan"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  os_type             = "Linux"
  sku_name            = var.sku_name
}

resource "azurerm_linux_web_app" "app" {
  name                = local.app_name
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  service_plan_id     = azurerm_service_plan.plan.id
  https_only          = true

  site_config {
    always_on           = false
    minimum_tls_version = "1.2"
    app_command_line = "gunicorn --bind=0.0.0.0 --timeout 600 --workers=1 --worker-class uvicorn.workers.UvicornWorker --access-logfile '-' --error-logfile '-' app:app"

    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    SCM_DO_BUILD_DURING_DEPLOYMENT = "true"
    ENABLE_ORYX_BUILD              = "true"
  }
}