"use strict";

const _ = require("lodash");
const { expect } = require("chai");
const { server } = require("./config/test.server.js");
const sequelize = require("../config/sequelize/setup.js");
const Test = require("./config/test.utils.js");

const uri = `${server.info.uri}/v0`;
const scope = {};

describe("User CRUD operations -", () => {
  before(async () => {
    await Test.setupDb();
    return Promise.resolve();
  });

  describe("GET /users/{userId}", () => {
    it("should read a given user's information if requester is an admin", async () => {
      // Create an admin user and a JWT access token for that user
      scope.user = await sequelize.models.User.create({
        email: `admin@example.com`,
      });
      await Test.assignRoleForUser({
        user: scope.user,
        roleName: "admin",
      });
      scope.accessToken = await scope.user.generateAccessToken();          
      const { statusCode, result } = await server.inject({
        method: "get",
        url: `${uri}/users/3`,
        headers: {
          authorization: `Bearer ${scope.accessToken}`,
        },
      });
      console.log(`accessToken is ${scope.accessToken}`)

      expect(statusCode).to.equal(200);
      return Promise.resolve();
    });
    it("should return 401 unauthorized if requester is not an admin", async () => {
      // Create a user and a JWT access token for that user
      scope.user = await sequelize.models.User.create({
        email: `user@example.com`,
      });
      scope.accessToken = await scope.user.generateAccessToken();          
      const { statusCode, result } = await server.inject({
        method: "get",
        url: `${uri}/users/2`,
        headers: {
          authorization: `Bearer ${scope.accessToken}`,
        },
      });
      expect(statusCode).to.equal(401);

      return Promise.resolve()
    });
  });

  describe("GET /self", () => {
    it("should read own information", async () => {
      // Create a user and a JWT access token for that user
      scope.user = await sequelize.models.User.create({
        email: `user@example.com`,
      });
      scope.accessToken = await scope.user.generateAccessToken();

      // Add 2 roles to the user
      await Test.assignRoleForUser({
        user: scope.user,
        roleName: "owner",
      });
      await Test.assignRoleForUser({
        user: scope.user,
        roleName: "member",
      });
      console.log(`Access token for user is\n${scope.accessToken}`)
      // Make the request
      const { statusCode, result } = await server.inject({
        method: "get",
        url: `${uri}/users/self`,
        headers: {
          authorization: `Bearer ${scope.accessToken}`,
        },
      });

      // Assert a proper response
      expect(statusCode).to.equal(200);
      expect(result.id).to.equal(scope.user.id);
      expect(result.uuid).to.equal(scope.user.uuid);
      expect(result.email).to.equal(scope.user.email);
      expect(result.roles.length).to.equal(2);
      expect(result.roles).to.have.members(["owner", "member"]);

      return Promise.resolve();
    });

    describe("generate Admin access token", () => {
      it("should read own information", async () => {
        // Create a user and a JWT access token for that user
        scope.user = await sequelize.models.User.create({
          email: `user@example.com`,
        });
        scope.accessToken = await scope.user.generateAccessToken();
  
        // Add 2 roles to the user
        await Test.assignRoleForUser({
          user: scope.user,
          roleName: "admin",
        });
        await Test.assignRoleForUser({
          user: scope.user,
          roleName: "member",
        });
        console.log(`Access token for admin is\n${scope.accessToken}`)
        return Promise.resolve();
      });
    });
  });
});
