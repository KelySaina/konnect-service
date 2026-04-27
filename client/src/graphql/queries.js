import { gql } from "@apollo/client";

export const ME_QUERY = gql`
  query Me {
    me {
      id
      email
      username
      first_name
      last_name
      phone
      avatar_url
      locale
      timezone
      email_verified
      active
      last_login_at
      createdAt
      roles {
        id
        name
        permissions {
          id
          name
        }
      }
      organizations {
        id
        name
        slug
      }
      addresses {
        id
        label
        street
        city
        postal_code
        country
        is_primary
      }
    }
  }
`;

export const USERS_QUERY = gql`
  query Users($page: Int, $pageSize: Int, $filter: UserFilter) {
    users(page: $page, pageSize: $pageSize, filter: $filter) {
      count
      page
      pageSize
      rows {
        id
        email
        username
        first_name
        last_name
        phone
        locale
        timezone
        active
        email_verified
        createdAt
        roles {
          id
          name
        }
        organizations {
          id
          name
        }
      }
    }
  }
`;

export const ROLES_QUERY = gql`
  query Roles {
    roles {
      id
      name
      description
      is_system
      permissions {
        id
        name
        resource
        action
      }
    }
  }
`;

export const PERMISSIONS_QUERY = gql`
  query Permissions {
    permissions {
      id
      name
      resource
      action
    }
  }
`;

export const CLIENTS_QUERY = gql`
  query Clients($page: Int, $pageSize: Int) {
    clients(page: $page, pageSize: $pageSize) {
      count
      page
      pageSize
      rows {
        id
        client_id
        name
        description
        redirect_uris
        allowed_scopes
        grant_types
        is_confidential
        active
        createdAt
      }
    }
  }
`;

export const ORGANIZATIONS_QUERY = gql`
  query Organizations($page: Int, $pageSize: Int) {
    organizations(page: $page, pageSize: $pageSize) {
      count
      page
      pageSize
      rows {
        id
        name
        slug
        description
        domain
        active
        createdAt
        members {
          id
          email
          username
        }
      }
    }
  }
`;

// ---------- Mutations ----------

export const CREATE_USER = gql`
  mutation CreateUser($input: CreateUserInput!) {
    createUser(input: $input) {
      id email username
    }
  }
`;

export const UPDATE_USER = gql`
  mutation UpdateUser($id: ID!, $input: UpdateUserInput!) {
    updateUser(id: $id, input: $input) {
      id email username first_name last_name phone locale timezone active
    }
  }
`;

export const DEACTIVATE_USER = gql`
  mutation DeactivateUser($id: ID!) {
    deactivateUser(id: $id) {
      id active
    }
  }
`;

export const ASSIGN_ROLE = gql`
  mutation AssignRole($userId: ID!, $roleId: ID!) {
    assignRole(userId: $userId, roleId: $roleId) {
      id
      roles { id name }
    }
  }
`;

export const REVOKE_ROLE = gql`
  mutation RevokeRole($userId: ID!, $roleId: ID!) {
    revokeRole(userId: $userId, roleId: $roleId) {
      id
      roles { id name }
    }
  }
`;

export const CREATE_ROLE = gql`
  mutation CreateRole($input: CreateRoleInput!) {
    createRole(input: $input) { id name description }
  }
`;

export const UPDATE_ROLE = gql`
  mutation UpdateRole($id: ID!, $input: UpdateRoleInput!) {
    updateRole(id: $id, input: $input) { id name description }
  }
`;

export const DELETE_ROLE = gql`
  mutation DeleteRole($id: ID!) {
    deleteRole(id: $id)
  }
`;

export const ASSIGN_PERMISSION = gql`
  mutation AssignPermission($roleId: ID!, $permissionId: ID!) {
    assignPermission(roleId: $roleId, permissionId: $permissionId) {
      id
      permissions { id name resource action }
    }
  }
`;

export const REVOKE_PERMISSION = gql`
  mutation RevokePermission($roleId: ID!, $permissionId: ID!) {
    revokePermission(roleId: $roleId, permissionId: $permissionId) {
      id
      permissions { id name resource action }
    }
  }
`;

export const CREATE_CLIENT = gql`
  mutation CreateClient($input: CreateClientInput!) {
    createClient(input: $input) {
      id client_id name redirect_uris active
    }
  }
`;

export const UPDATE_CLIENT = gql`
  mutation UpdateClient($id: ID!, $input: UpdateClientInput!) {
    updateClient(id: $id, input: $input) {
      id name description redirect_uris allowed_scopes grant_types active
    }
  }
`;

export const REVOKE_CLIENT = gql`
  mutation RevokeClient($id: ID!) {
    revokeClient(id: $id) {
      id active
    }
  }
`;

export const CREATE_ORGANIZATION = gql`
  mutation CreateOrganization($input: CreateOrganizationInput!) {
    createOrganization(input: $input) {
      id name slug description domain
    }
  }
`;

export const UPDATE_ORGANIZATION = gql`
  mutation UpdateOrganization($id: ID!, $input: UpdateOrganizationInput!) {
    updateOrganization(id: $id, input: $input) {
      id name slug description domain active
    }
  }
`;

export const ADD_ORG_MEMBER = gql`
  mutation AddOrganizationMember($organizationId: ID!, $userId: ID!) {
    addOrganizationMember(organizationId: $organizationId, userId: $userId) {
      id
      members { id email username }
    }
  }
`;

export const REMOVE_ORG_MEMBER = gql`
  mutation RemoveOrganizationMember($organizationId: ID!, $userId: ID!) {
    removeOrganizationMember(organizationId: $organizationId, userId: $userId) {
      id
      members { id email username }
    }
  }
`;
