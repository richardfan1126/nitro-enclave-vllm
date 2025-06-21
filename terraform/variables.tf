variable "project_name" {
  type        = string
  description = "The project name that will be tagged in the resources"
}

variable "eif_artifact_path" {
  type        = string
  description = "The full OCI path of the EIF"
}

variable "enclave_memory_size" {
  type        = string
  description = "The memory size allocate to the enclave (in MiB)"
}
