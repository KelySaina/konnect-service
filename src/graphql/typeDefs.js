const gql = require("graphql-tag");

const typeDefs = gql`
  scalar DateTime

  type User {
    id: ID!
    email: String!
    username: String!
    first_name: String
    last_name: String
    phone: String
    avatar_url: String
    date_of_birth: String
    locale: String
    timezone: String
    email_verified: Boolean
    phone_verified: Boolean
    active: Boolean
    metadata: JSON
    last_login_at: DateTime
    createdAt: DateTime
    updatedAt: DateTime
    addresses: [Address!]
    roles: [Role!]
    organizations: [Organization!]
  }

  type Address {
    id: ID!
    user_id: ID!
    label: String
    street: String
    street2: String
    city: String
    state: String
    postal_code: String
    country: String
    is_primary: Boolean
  }

  type Role {
    id: ID!
    name: String!
    description: String
    is_system: Boolean
    permissions: [Permission!]
  }

  type Permission {
    id: ID!
    name: String!
    description: String
    resource: String!
    action: String!
  }

  type OAuthClient {
    id: ID!
    client_id: String!
    name: String!
    description: String
    logo_url: String
    redirect_uris: [String!]
    allowed_scopes: [String!]
    grant_types: [String!]
    token_endpoint_auth_method: String
    is_confidential: Boolean
    active: Boolean
    createdAt: DateTime
    updatedAt: DateTime
  }

  type Organization {
    id: ID!
    name: String!
    slug: String!
    description: String
    logo_url: String
    domain: String
    active: Boolean
    metadata: JSON
    members: [User!]
    createdAt: DateTime
    updatedAt: DateTime
  }

  type PaginatedUsers {
    rows: [User!]!
    count: Int!
    page: Int!
    pageSize: Int!
  }

  type PaginatedClients {
    rows: [OAuthClient!]!
    count: Int!
    page: Int!
    pageSize: Int!
  }

  type PaginatedOrganizations {
    rows: [Organization!]!
    count: Int!
    page: Int!
    pageSize: Int!
  }

  scalar JSON

  # ---------- Inputs ----------

  input UserFilter {
    active: Boolean
    email_verified: Boolean
    role: String
    search: String
  }

  input CreateUserInput {
    email: String!
    username: String!
    password: String!
    first_name: String
    last_name: String
    phone: String
    locale: String
    timezone: String
  }

  input UpdateUserInput {
    email: String
    username: String
    first_name: String
    last_name: String
    phone: String
    locale: String
    timezone: String
    active: Boolean
  }

  input CreateAddressInput {
    label: String
    street: String
    street2: String
    city: String
    state: String
    postal_code: String
    country: String
    is_primary: Boolean
  }

  input CreateClientInput {
    name: String!
    description: String
    redirect_uris: [String!]!
    allowed_scopes: [String!]
    grant_types: [String!]
    is_confidential: Boolean
  }

  input UpdateClientInput {
    name: String
    description: String
    redirect_uris: [String!]
    allowed_scopes: [String!]
    grant_types: [String!]
    active: Boolean
  }

  input CreateRoleInput {
    name: String!
    description: String
  }

  input UpdateRoleInput {
    name: String
    description: String
  }

  input CreateOrganizationInput {
    name: String!
    slug: String!
    description: String
    domain: String
  }

  input UpdateOrganizationInput {
    name: String
    description: String
    domain: String
    active: Boolean
  }

  # ---------- Queries ----------

  type Query {
    "Get current authenticated user profile"
    me: User

    "Get a user by ID (admin)"
    user(id: ID!): User

    "List users with pagination and filters (admin)"
    users(page: Int, pageSize: Int, filter: UserFilter): PaginatedUsers!

    "Get a role by ID"
    role(id: ID!): Role

    "List all roles"
    roles: [Role!]!

    "List all permissions"
    permissions: [Permission!]!

    "Get an OAuth client by ID"
    client(id: ID!): OAuthClient

    "List OAuth clients (admin)"
    clients(page: Int, pageSize: Int): PaginatedClients!

    "Get an organization by ID"
    organization(id: ID!): Organization

    "List organizations (admin)"
    organizations(page: Int, pageSize: Int): PaginatedOrganizations!
  }

  # ---------- Mutations ----------

  type Mutation {
    "Create a new user (admin)"
    createUser(input: CreateUserInput!): User!

    "Update a user (admin or self)"
    updateUser(id: ID!, input: UpdateUserInput!): User!

    "Deactivate a user"
    deactivateUser(id: ID!): User!

    "Add address to user"
    addAddress(userId: ID!, input: CreateAddressInput!): Address!

    "Remove address"
    removeAddress(id: ID!): Boolean!

    "Assign role to user"
    assignRole(userId: ID!, roleId: ID!): User!

    "Revoke role from user"
    revokeRole(userId: ID!, roleId: ID!): User!

    "Create a role (admin)"
    createRole(input: CreateRoleInput!): Role!

    "Delete a role (admin, non-system)"
    deleteRole(id: ID!): Boolean!

    "Update a role (admin)"
    updateRole(id: ID!, input: UpdateRoleInput!): Role!

    "Assign permission to role"
    assignPermission(roleId: ID!, permissionId: ID!): Role!

    "Revoke permission from role"
    revokePermission(roleId: ID!, permissionId: ID!): Role!

    "Register a new OAuth client"
    createClient(input: CreateClientInput!): OAuthClient!

    "Update an OAuth client"
    updateClient(id: ID!, input: UpdateClientInput!): OAuthClient!

    "Revoke (deactivate) an OAuth client"
    revokeClient(id: ID!): OAuthClient!

    "Create an organization"
    createOrganization(input: CreateOrganizationInput!): Organization!

    "Update an organization"
    updateOrganization(id: ID!, input: UpdateOrganizationInput!): Organization!

    "Add member to organization"
    addOrganizationMember(organizationId: ID!, userId: ID!): Organization!

    "Remove member from organization"
    removeOrganizationMember(organizationId: ID!, userId: ID!): Organization!
  }
`;

module.exports = typeDefs;
