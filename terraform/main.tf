# ============================================================
# Lab DevSecOps - Azure Infrastructure
#   Azure Container Instances (ACI)
#   Azure Database for MySQL Flexible Server
#   Azure Virtual Network + Subnets
#   Azure Application Gateway (simplificado: ACI directo)
#   Azure Key Vault
# ============================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# ─── Variables ───────────────────────────────────────────────
# Los valores concretos se definen en terraform.tfvars

variable "location" {
  description = "Azure region donde se desplegará el laboratorio. Ejemplo: centralus, eastus2, westus2."
  type        = string
}

variable "resource_group_name" {
  description = "Nombre del Resource Group"
  type        = string
}

variable "app_name" {
  description = "Nombre base de la aplicación"
  type        = string
}

variable "db_admin_username" {
  description = "Usuario admin de MySQL"
  type        = string
  sensitive   = true
}

variable "container_image" {
  description = "Imagen Docker de la app"
  type        = string
}

variable "tags" {
  description = "Tags comunes para los recursos"
  type        = map(string)
}

# ─── Data sources ────────────────────────────────────────────

data "azurerm_client_config" "current" {}

# ─── Resource Group ──────────────────────────────────────────

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# ─── Virtual Network ─────────────────────────────────────────
# Equivalente a VPC en AWS

resource "azurerm_virtual_network" "main" {
  name                = "vnet-${var.app_name}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.0.0.0/16"]
  tags                = var.tags
}

# ─── Subnet pública ──────────────────────────────────────────
# Para la app / capa de entrada

resource "azurerm_subnet" "public" {
  name                 = "snet-public"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]

  delegation {
    name = "aci-delegation"

    service_delegation {
      name    = "Microsoft.ContainerInstance/containerGroups"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

# ─── Subnet privada ──────────────────────────────────────────
# Para MySQL Flexible Server

resource "azurerm_subnet" "private" {
  name                 = "snet-private"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]

  delegation {
    name = "mysql-delegation"

    service_delegation {
      name    = "Microsoft.DBforMySQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# ─── Network Security Groups ─────────────────────────────────
# Equivalente conceptual a Security Groups en AWS

resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags

  security_rule {
    name                       = "allow-http"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5000"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "db" {
  name                = "nsg-db"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags

  security_rule {
    name                       = "allow-mysql-from-app"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3306"
    source_address_prefix      = "10.0.1.0/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-public-mysql"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3306"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

# Asociaciones NSG ↔ Subnet

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = azurerm_network_security_group.app.id
}

resource "azurerm_subnet_network_security_group_association" "db" {
  subnet_id                 = azurerm_subnet.private.id
  network_security_group_id = azurerm_network_security_group.db.id
}

# ─── Private DNS para MySQL Flexible Server ──────────────────
# Necesario cuando MySQL Flexible Server usa private access

resource "azurerm_private_dns_zone" "mysql" {
  name                = "${var.app_name}.mysql.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "mysql" {
  name                  = "mysql-dns-link-${var.app_name}"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.mysql.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
  tags                  = var.tags
}

# ─── Key Vault ───────────────────────────────────────────────
# Equivalente a AWS Secrets Manager

resource "random_string" "kv_suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-${var.app_name}-${random_string.kv_suffix.result}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
      "Purge"
    ]
  }

  tags = var.tags
}

# ─── Password seguro para MySQL ──────────────────────────────

resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  value        = random_password.db_password.result
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [
    azurerm_key_vault.main
  ]
}

# ─── MySQL Flexible Server ───────────────────────────────────
# Equivalente conceptual a Amazon RDS MySQL

resource "azurerm_mysql_flexible_server" "main" {
  name                   = "mysql-${var.app_name}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  administrator_login    = var.db_admin_username
  administrator_password = random_password.db_password.result

  sku_name = "B_Standard_B1ms"
  version  = "8.0.21"

  delegated_subnet_id = azurerm_subnet.private.id
  private_dns_zone_id = azurerm_private_dns_zone.mysql.id

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false

  tags = var.tags

  depends_on = [
    azurerm_private_dns_zone_virtual_network_link.mysql
  ]
}

resource "azurerm_mysql_flexible_database" "students" {
  name                = "studentsdb"
  resource_group_name = azurerm_resource_group.main.name
  server_name         = azurerm_mysql_flexible_server.main.name
  charset             = "utf8mb4"
  collation           = "utf8mb4_unicode_ci"
}

# ─── Azure Container Instance ────────────────────────────────
# Equivalente simplificado a EC2 + aplicación

resource "azurerm_container_group" "app" {
  name                = "aci-${var.app_name}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  ip_address_type     = "Public"
  os_type             = "Linux"

  identity {
    type = "SystemAssigned"
  }

  container {
    name   = "student-records"
    image  = var.container_image
    cpu    = "0.5"
    memory = "1.0"

    ports {
      port     = 80
      protocol = "TCP"
    }

    environment_variables = {
      FLASK_ENV = "production"
    }

    secure_environment_variables = {
      DB_PASSWORD = random_password.db_password.result
      DB_HOST     = azurerm_mysql_flexible_server.main.fqdn
      DB_USER     = var.db_admin_username
      DB_NAME     = azurerm_mysql_flexible_database.students.name
    }
  }

  tags = var.tags
}

# ─── Outputs ─────────────────────────────────────────────────

output "app_url" {
  description = "URL pública de la aplicación"
  value       = "http://${azurerm_container_group.app.ip_address}:80"
}

output "key_vault_name" {
  description = "Nombre del Key Vault"
  value       = azurerm_key_vault.main.name
}

output "db_host" {
  description = "FQDN del servidor MySQL"
  value       = azurerm_mysql_flexible_server.main.fqdn
}

output "resource_group" {
  description = "Resource Group creado"
  value       = azurerm_resource_group.main.name
}

output "location" {
  description = "Región donde se desplegó el laboratorio"
  value       = azurerm_resource_group.main.location
}