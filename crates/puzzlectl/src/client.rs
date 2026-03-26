// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use zbus::Connection;

/// D-Bus client for communicating with puzzled.
///
/// The `Connection` is heap-allocated and leaked to produce a `'static` reference,
/// which satisfies the lifetime requirement of `ManagerProxy`. This is acceptable
/// because `PuzzledClient` lives for the entire duration of the CLI process, so the
/// leaked `Connection` is effectively freed at process exit.
pub struct PuzzledClient {
    /// Leaked reference — lives for process lifetime. Not dropped, freed at exit.
    _connection: &'static Connection,
    proxy: ManagerProxy<'static>,
}

/// Auto-generated proxy for org.lobstertrap.PuzzlePod1.Manager.
#[zbus::proxy(
    interface = "org.lobstertrap.PuzzlePod1.Manager",
    default_service = "org.lobstertrap.PuzzlePod1",
    default_path = "/org/lobstertrap/PuzzlePod1/Manager"
)]
trait Manager {
    async fn create_branch(
        &self,
        profile: &str,
        base_path: &str,
        command_json: &str,
    ) -> zbus::Result<String>;
    async fn activate_branch(&self, branch_id: &str, command_json: &str) -> zbus::Result<String>;
    async fn commit_branch(&self, branch_id: &str) -> zbus::Result<String>;
    async fn rollback_branch(&self, branch_id: &str, reason: &str) -> zbus::Result<bool>;
    async fn inspect_branch(&self, branch_id: &str) -> zbus::Result<String>;
    async fn list_branches(&self) -> zbus::Result<String>;
    async fn diff_branch(&self, branch_id: &str) -> zbus::Result<String>;
    async fn list_agents(&self) -> zbus::Result<String>;
    async fn kill_agent(&self, branch_id: &str) -> zbus::Result<bool>;
    async fn reload_policy(&self) -> zbus::Result<(bool, String)>;
    async fn query_audit_events(&self, filter_json: &str) -> zbus::Result<String>;
    async fn export_audit_events(&self, format: &str) -> zbus::Result<String>;
    async fn approve_branch(&self, branch_id: &str) -> zbus::Result<String>;
    async fn reject_branch(&self, branch_id: &str, reason: &str) -> zbus::Result<bool>;
    async fn unregister_agent(&self, branch_id: &str) -> zbus::Result<bool>;
    async fn agent_info(&self, branch_id: &str) -> zbus::Result<String>;
    async fn store_credential(
        &self,
        name: &str,
        credential_type: &str,
        value_source: &str,
        config_json: &str,
    ) -> zbus::Result<bool>;
    async fn remove_credential(&self, credential_name: &str) -> zbus::Result<bool>;
    async fn rotate_credential(
        &self,
        credential_name: &str,
        value_source: &str,
    ) -> zbus::Result<bool>;
    async fn list_credentials(&self, profile_name: &str) -> zbus::Result<String>;
    /// §3.4 G19: Provision credentials for a branch.
    async fn provision_credentials(&self, branch_id: &str) -> zbus::Result<String>;
    /// §3.4 G19: Unlock a passphrase-encrypted credential.
    async fn unlock_credential(
        &self,
        credential_name: &str,
        passphrase: &str,
    ) -> zbus::Result<bool>;
    async fn verify_attestation_chain(&self, branch_id: &str) -> zbus::Result<String>;
    async fn get_inclusion_proof(&self, seq: u64) -> zbus::Result<String>;
    async fn get_consistency_proof(&self, from_size: u64, to_size: u64) -> zbus::Result<String>;
    async fn export_attestation_bundle(&self, branch_id: &str) -> zbus::Result<String>;
    async fn get_attestation_public_key(&self) -> zbus::Result<String>;
    async fn generate_seccomp_profile(&self, branch_id: &str) -> zbus::Result<String>;
    async fn generate_landlock_rules(&self, branch_id: &str) -> zbus::Result<String>;
    async fn attach_governance(
        &self,
        branch_id: &str,
        container_pid: u32,
        container_id: &str,
    ) -> zbus::Result<bool>;
    async fn trigger_governance(&self, branch_id: &str) -> zbus::Result<String>;
    async fn ensure_branch(&self, profile: &str, base_path: &str) -> zbus::Result<String>;
}

impl PuzzledClient {
    /// Connect to puzzled over D-Bus.
    pub async fn connect(bus_type: &str) -> Result<Self> {
        let connection = match bus_type {
            "session" => Connection::session()
                .await
                .context("connecting to session bus")?,
            _ => Connection::system()
                .await
                .context("connecting to system bus")?,
        };

        // Leak the connection to obtain a 'static reference, satisfying the
        // ManagerProxy lifetime requirement. This is safe: the CLI process owns
        // a single PuzzledClient for its entire lifetime, so the Connection is
        // effectively freed at process exit. This avoids the previous unsafe
        // transmute of the proxy lifetime.
        let connection: &'static Connection = Box::leak(Box::new(connection));

        let proxy = ManagerProxy::new(connection)
            .await
            .context("creating puzzled proxy")?;

        Ok(Self {
            _connection: connection,
            proxy,
        })
    }

    pub async fn list_branches(&self) -> Result<String> {
        self.proxy
            .list_branches()
            .await
            .context("ListBranches call failed")
    }

    pub async fn inspect_branch(&self, id: &str) -> Result<String> {
        self.proxy
            .inspect_branch(id)
            .await
            .context("InspectBranch call failed")
    }

    #[allow(dead_code)] // D-Bus API method; approve_branch is the governance-aware path
    pub async fn commit_branch(&self, id: &str) -> Result<String> {
        self.proxy
            .commit_branch(id)
            .await
            .context("CommitBranch call failed")
    }

    pub async fn rollback_branch(&self, id: &str, reason: &str) -> Result<bool> {
        self.proxy
            .rollback_branch(id, reason)
            .await
            .context("RollbackBranch call failed")
    }

    pub async fn diff_branch(&self, id: &str) -> Result<String> {
        self.proxy
            .diff_branch(id)
            .await
            .context("DiffBranch call failed")
    }

    pub async fn list_agents(&self) -> Result<String> {
        self.proxy
            .list_agents()
            .await
            .context("ListAgents call failed")
    }

    pub async fn kill_agent(&self, id: &str) -> Result<bool> {
        self.proxy
            .kill_agent(id)
            .await
            .context("KillAgent call failed")
    }

    pub async fn create_branch(
        &self,
        profile: &str,
        base_path: &str,
        command_json: &str,
    ) -> Result<String> {
        self.proxy
            .create_branch(profile, base_path, command_json)
            .await
            .context("CreateBranch call failed")
    }

    pub async fn activate_branch(&self, branch_id: &str, command_json: &str) -> Result<String> {
        self.proxy
            .activate_branch(branch_id, command_json)
            .await
            .context("ActivateBranch call failed")
    }

    pub async fn reload_policy(&self) -> Result<(bool, String)> {
        self.proxy
            .reload_policy()
            .await
            .context("ReloadPolicy call failed")
    }

    pub async fn query_audit_events(&self, filter_json: &str) -> Result<String> {
        self.proxy
            .query_audit_events(filter_json)
            .await
            .context("QueryAuditEvents call failed")
    }

    pub async fn export_audit_events(&self, format: &str) -> Result<String> {
        self.proxy
            .export_audit_events(format)
            .await
            .context("ExportAuditEvents call failed")
    }

    pub async fn approve_branch(&self, id: &str) -> Result<String> {
        self.proxy
            .approve_branch(id)
            .await
            .context("ApproveBranch call failed")
    }

    pub async fn reject_branch(&self, id: &str, reason: &str) -> Result<bool> {
        self.proxy
            .reject_branch(id, reason)
            .await
            .context("RejectBranch call failed")
    }

    #[allow(dead_code)] // Public API for agent lifecycle management
    pub async fn unregister_agent(&self, id: &str) -> Result<bool> {
        self.proxy
            .unregister_agent(id)
            .await
            .context("UnregisterAgent call failed")
    }

    pub async fn agent_info(&self, id: &str) -> Result<String> {
        self.proxy
            .agent_info(id)
            .await
            .context("AgentInfo call failed")
    }

    pub async fn store_credential(
        &self,
        name: &str,
        credential_type: &str,
        value_source: &str,
        config_json: &str,
    ) -> Result<bool> {
        self.proxy
            .store_credential(name, credential_type, value_source, config_json)
            .await
            .context("StoreCredential call failed")
    }

    pub async fn remove_credential(&self, credential_name: &str) -> Result<bool> {
        self.proxy
            .remove_credential(credential_name)
            .await
            .context("RemoveCredential call failed")
    }

    pub async fn rotate_credential(
        &self,
        credential_name: &str,
        value_source: &str,
    ) -> Result<bool> {
        self.proxy
            .rotate_credential(credential_name, value_source)
            .await
            .context("RotateCredential call failed")
    }

    pub async fn list_credentials(&self, profile_name: &str) -> Result<String> {
        self.proxy
            .list_credentials(profile_name)
            .await
            .context("ListCredentials call failed")
    }

    /// §3.4 G19: Provision credentials for a branch.
    pub async fn provision_credentials(&self, branch_id: &str) -> Result<String> {
        self.proxy
            .provision_credentials(branch_id)
            .await
            .context("ProvisionCredentials call failed")
    }

    /// §3.4 G19: Unlock a passphrase-encrypted credential.
    pub async fn unlock_credential(&self, credential_name: &str, passphrase: &str) -> Result<bool> {
        self.proxy
            .unlock_credential(credential_name, passphrase)
            .await
            .context("UnlockCredential call failed")
    }

    pub async fn verify_attestation_chain(&self, branch_id: &str) -> Result<String> {
        self.proxy
            .verify_attestation_chain(branch_id)
            .await
            .context("VerifyAttestationChain call failed")
    }

    pub async fn get_inclusion_proof(&self, seq: u64) -> Result<String> {
        self.proxy
            .get_inclusion_proof(seq)
            .await
            .context("GetInclusionProof call failed")
    }

    pub async fn get_consistency_proof(&self, from_size: u64, to_size: u64) -> Result<String> {
        self.proxy
            .get_consistency_proof(from_size, to_size)
            .await
            .context("GetConsistencyProof call failed")
    }

    pub async fn export_attestation_bundle(&self, branch_id: &str) -> Result<String> {
        self.proxy
            .export_attestation_bundle(branch_id)
            .await
            .context("ExportAttestationBundle call failed")
    }

    pub async fn get_attestation_public_key(&self) -> Result<String> {
        self.proxy
            .get_attestation_public_key()
            .await
            .context("GetAttestationPublicKey call failed")
    }

    pub async fn generate_seccomp_profile(&self, id: &str) -> Result<String> {
        self.proxy
            .generate_seccomp_profile(id)
            .await
            .context("GenerateSeccompProfile call failed")
    }

    pub async fn generate_landlock_rules(&self, id: &str) -> Result<String> {
        self.proxy
            .generate_landlock_rules(id)
            .await
            .context("GenerateLandlockRules call failed")
    }

    pub async fn ensure_branch(&self, profile: &str, base_path: &str) -> Result<String> {
        self.proxy
            .ensure_branch(profile, base_path)
            .await
            .context("EnsureBranch call failed")
    }

    /// Access the leaked D-Bus connection for signal subscription.
    pub fn connection(&self) -> &'static Connection {
        self._connection
    }
}
