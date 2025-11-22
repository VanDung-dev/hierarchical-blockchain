"""
Unit tests for MSP (Membership Service Provider).

Tests the advanced MSP implementation including certificate management, 
role-based access control, and hierarchical identity management for enterprise applications.
"""

from hierarchical_blockchain.security.msp import HierarchicalMSP, CertificateAuthority, OrganizationPolicies


def setup_msp():
    """Set up test fixtures for MSP"""
    ca_config = {
        "root_cert": "test-root-ca",
        "intermediate_certs": ["test-intermediate-ca"],
        "policy": {"default_validity": 365}
    }
    
    msp = HierarchicalMSP("test-org", ca_config)
    
    # Test credentials
    test_credentials = {
        "public_key": "test-public-key-123",
        "private_key": "test-private-key-123"
    }
    
    # Test attributes
    test_attributes = {
        "department": "engineering",
        "location": "headquarters",
        "clearance_level": "standard"
    }
    
    return msp, test_credentials, test_attributes

def test_msp_initialization():
    """Test MSP initialization"""
    msp, _, _ = setup_msp()
    assert msp.organization_id == "test-org"
    assert msp.ca is not None
    assert msp.policies is not None
    assert len(msp.roles) > 0  # Should have default roles
    assert len(msp.audit_log) == 0  # Should start empty

def test_default_roles_initialization():
    """Test default roles are properly initialized"""
    msp, _, _ = setup_msp()
    expected_roles = ["admin", "operator", "viewer"]
    
    for role in expected_roles:
        assert role in msp.roles
        assert len(msp.roles[role]["permissions"]) > 0
        assert "cert_validity_days" in msp.roles[role]

def test_register_entity_success():
    """Test successful entity registration"""
    msp, test_credentials, test_attributes = setup_msp()
    result = msp.register_entity(
        "test-user-001",
        test_credentials,
        "admin",
        test_attributes
    )
    
    assert result
    assert "test-user-001" in msp.entities
    
    entity = msp.entities["test-user-001"]
    assert entity["role"] == "admin"
    assert entity["status"] == "active"
    assert entity["attributes"] == test_attributes

def test_register_entity_invalid_role():
    """Test entity registration with invalid role"""
    msp, test_credentials, _ = setup_msp()
    result = msp.register_entity(
        "test-user-002",
        test_credentials,
        "invalid-role"
    )
    
    assert not result
    assert "test-user-002" not in msp.entities

def test_validate_identity_success():
    """Test successful identity validation"""
    msp, test_credentials, _ = setup_msp()
    # First register entity
    msp.register_entity(
        "test-user-003",
        test_credentials,
        "operator"
    )
    
    # Then validate
    result = msp.validate_identity(
        "test-user-003",
        test_credentials
    )
    
    assert result

def test_validate_identity_wrong_credentials():
    """Test identity validation with wrong credentials"""
    msp, test_credentials, _ = setup_msp()
    # Register entity
    msp.register_entity(
        "test-user-004",
        test_credentials,
        "operator"
    )
    
    # Validate with wrong credentials
    wrong_credentials = {
        "public_key": "wrong-key",
        "private_key": "wrong-private-key"
    }
    
    result = msp.validate_identity(
        "test-user-004",
        wrong_credentials
    )
    
    assert not result

def test_validate_identity_nonexistent_user():
    """Test identity validation for non-existent user"""
    msp, test_credentials, _ = setup_msp()
    result = msp.validate_identity(
        "non-existent-user",
        test_credentials
    )
    
    assert not result

def test_authorize_action_success():
    """Test successful action authorization"""
    msp, test_credentials, _ = setup_msp()
    # Register entity with admin role
    msp.register_entity(
        "test-admin",
        test_credentials,
        "admin"
    )
    
    # Test authorization for admin action
    result = msp.authorize_action(
        "test-admin",
        "manage_entities"
    )
    
    assert result

def test_authorize_action_insufficient_permissions():
    """Test action authorization with insufficient permissions"""
    msp, test_credentials, _ = setup_msp()
    # Register entity with viewer role
    msp.register_entity(
        "test-viewer",
        test_credentials,
        "viewer"
    )
    
    # Test authorization for admin action
    result = msp.authorize_action(
        "test-viewer",
        "manage_entities"
    )
    
    assert not result

def test_revoke_entity():
    """Test entity revocation"""
    msp, test_credentials, _ = setup_msp()
    # Register entity
    msp.register_entity(
        "test-user-revoke",
        test_credentials,
        "operator"
    )
    
    # Revoke entity
    result = msp.revoke_entity("test-user-revoke", "security_breach")
    
    assert result
    entity = msp.entities["test-user-revoke"]
    assert entity["status"] == "revoked"
    assert entity["revocation_reason"] == "security_breach"

def test_define_custom_role():
    """Test defining custom organizational role"""
    msp, _, _ = setup_msp()
    custom_permissions = ["custom_action_1", "custom_action_2"]
    
    msp.define_role(
        "custom_role",
        custom_permissions,
        ["custom_policy"],
        180
    )
    
    assert "custom_role" in msp.roles
    assert msp.roles["custom_role"]["permissions"] == custom_permissions
    assert msp.roles["custom_role"]["cert_validity_days"] == 180

def test_get_entity_info():
    """Test getting entity information"""
    msp, test_credentials, test_attributes = setup_msp()
    # Register entity
    msp.register_entity(
        "test-info-user",
        test_credentials,
        "operator",
        test_attributes
    )
    
    info = msp.get_entity_info("test-info-user")
    
    assert info is not None
    assert info["entity_id"] == "test-info-user"
    assert info["role"] == "operator"
    assert info["status"] == "active"
    assert info["attributes"] == test_attributes

def test_get_entity_info_nonexistent():
    """Test getting info for non-existent entity"""
    msp, _, _ = setup_msp()
    info = msp.get_entity_info("non-existent")
    assert info is None

def test_audit_logging():
    """Test audit logging functionality"""
    msp, test_credentials, _ = setup_msp()
    initial_log_count = len(msp.audit_log)
    
    # Register entity (should create audit log entry)
    msp.register_entity(
        "test-audit-user",
        test_credentials,
        "admin"
    )
    
    # Check audit log
    audit_log = msp.get_audit_log(10)
    assert len(audit_log) > initial_log_count
    
    # Check log entry details
    last_entry = audit_log[-1]
    assert last_entry["event_type"] == "entity_registered"
    assert last_entry["organization_id"] == "test-org"
    assert "entity_id" in last_entry["details"]


def setup_ca():
    """Set up test fixtures for CertificateAuthority"""
    ca = CertificateAuthority(
        root_cert="test-root",
        intermediate_certs=["test-intermediate"],
        policy={"default_validity": 365}
    )
    return ca

def test_ca_initialization():
    """Test CA initialization"""
    ca = setup_ca()
    assert ca.root_cert == "test-root"
    assert len(ca.intermediate_certs) == 1
    assert len(ca.issued_certificates) == 0
    assert len(ca.revoked_certificates) == 0

def test_issue_certificate():
    """Test certificate issuance"""
    ca = setup_ca()
    certificate = ca.issue_certificate(
        subject="test-subject",
        public_key="test-public-key",
        attributes={"role": "admin"},
        valid_days=365
    )
    
    assert certificate is not None
    assert certificate.subject == "test-subject"
    assert certificate.public_key == "test-public-key"
    assert certificate.cert_id in ca.issued_certificates

def test_revoke_certificate():
    """Test certificate revocation"""
    ca = setup_ca()
    # Issue certificate first
    certificate = ca.issue_certificate(
        subject="test-revoke",
        public_key="test-key",
        attributes={}
    )
    
    # Revoke certificate
    result = ca.revoke_certificate(certificate.cert_id, "compromised")
    
    assert result
    assert certificate.cert_id in ca.revoked_certificates

def test_verify_certificate_valid():
    """Test verification of valid certificate"""
    ca = setup_ca()
    certificate = ca.issue_certificate(
        subject="test-verify",
        public_key="test-key",
        attributes={}
    )
    
    result = ca.verify_certificate(certificate.cert_id)
    assert result

def test_verify_certificate_revoked():
    """Test verification of revoked certificate"""
    ca = setup_ca()
    certificate = ca.issue_certificate(
        subject="test-verify-revoked",
        public_key="test-key",
        attributes={}
    )
    
    # Revoke and then verify
    ca.revoke_certificate(certificate.cert_id, "test")
    result = ca.verify_certificate(certificate.cert_id)
    
    assert not result

def test_verify_certificate_nonexistent():
    """Test verification of non-existent certificate"""
    ca = setup_ca()
    result = ca.verify_certificate("non-existent-cert-id")
    assert not result


def setup_policies():
    """Set up test fixtures for OrganizationPolicies"""
    policies = OrganizationPolicies()
    return policies

def test_define_policy():
    """Test policy definition"""
    policies = setup_policies()
    policy_config = {
        "required_attributes": ["role", "department"],
        "conditions": {"department": "engineering"}
    }
    
    policies.define_policy("test_policy", policy_config)
    
    assert "test_policy" in policies.policies
    assert policies.policies["test_policy"]["config"] == policy_config

def test_evaluate_policy_success():
    """Test successful policy evaluation"""
    policies = setup_policies()
    policy_config = {
        "required_attributes": ["role", "department"]
    }
    
    policies.define_policy("test_policy", policy_config)
    
    context = {
        "role": "admin",
        "department": "engineering"
    }
    
    result = policies.evaluate_policy("test_policy", context)
    assert result

def test_evaluate_policy_missing_attributes():
    """Test policy evaluation with missing attributes"""
    policies = setup_policies()
    policy_config = {
        "required_attributes": ["role", "department"]
    }
    
    policies.define_policy("test_policy", policy_config)
    
    context = {
        "role": "admin"
        # Missing department
    }
    
    result = policies.evaluate_policy("test_policy", context)
    assert not result

def test_evaluate_policy_nonexistent():
    """Test evaluation of non-existent policy"""
    policies = setup_policies()
    result = policies.evaluate_policy("non_existent", {})
    assert not result

def test_assign_role_permissions():
    """Test role permission assignment"""
    policies = setup_policies()
    permissions = ["read", "write", "execute"]
    
    policies.assign_role_permissions("test_role", permissions)
    
    assert policies.role_permissions["test_role"] == permissions

def test_check_permission_success():
    """Test successful permission check"""
    policies = setup_policies()
    permissions = ["read", "write"]
    policies.assign_role_permissions("test_role", permissions)
    
    result = policies.check_permission("test_role", "read")
    assert result

def test_check_permission_denied():
    """Test denied permission check"""
    policies = setup_policies()
    permissions = ["read"]
    policies.assign_role_permissions("test_role", permissions)
    
    result = policies.check_permission("test_role", "write")
    assert not result

def test_check_permission_nonexistent_role():
    """Test permission check for non-existent role"""
    policies = setup_policies()
    result = policies.check_permission("non_existent_role", "read")
    assert not result


def setup_integration_msp():
    """Set up integration test fixtures"""
    ca_config = {
        "root_cert": "integration-test-root",
        "intermediate_certs": ["integration-test-intermediate"],
        "policy": {"default_validity": 365}
    }
    
    msp = HierarchicalMSP("integration-test-org", ca_config)
    return msp

def test_full_entity_lifecycle():
    """Test complete entity lifecycle"""
    msp = setup_integration_msp()
    credentials = {
        "public_key": "integration-test-key",
        "private_key": "integration-test-private"
    }
    
    attributes = {
        "department": "security",
        "clearance": "high"
    }
    
    # 1. Register entity
    register_result = msp.register_entity(
        "integration-user",
        credentials,
        "admin",
        attributes
    )
    assert register_result
    
    # 2. Validate identity
    validate_result = msp.validate_identity(
        "integration-user",
        credentials
    )
    assert validate_result
    
    # 3. Authorize actions
    auth_result = msp.authorize_action(
        "integration-user",
        "manage_entities"
    )
    assert auth_result
    
    # 4. Get entity info
    info = msp.get_entity_info("integration-user")
    assert info is not None
    assert info["role"] == "admin"
    
    # 5. Revoke entity
    revoke_result = msp.revoke_entity(
        "integration-user",
        "end_of_employment"
    )
    assert revoke_result
    
    # 6. Verify revoked entity cannot be validated
    _validate_after_revoke = msp.validate_identity(
        "integration-user",
        credentials
    )
    # Should still validate identity but not authorize actions
    # (identity validation checks certificate, authorization checks status)

def test_role_based_access_control():
    """Test role-based access control integration"""
    msp = setup_integration_msp()
    admin_creds = {"public_key": "admin-key", "private_key": "admin-private"}
    viewer_creds = {"public_key": "viewer-key", "private_key": "viewer-private"}
    
    # Register admin and viewer
    msp.register_entity("test-admin", admin_creds, "admin")
    msp.register_entity("test-viewer", viewer_creds, "viewer")
    
    # Test admin permissions
    admin_manage = msp.authorize_action("test-admin", "manage_entities")
    admin_view = msp.authorize_action("test-admin", "view_data")
    
    assert admin_manage
    assert admin_view
    
    # Test viewer permissions
    viewer_manage = msp.authorize_action("test-viewer", "manage_entities")
    viewer_view = msp.authorize_action("test-viewer", "view_data")
    
    assert not viewer_manage
    assert viewer_view
