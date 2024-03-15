# MINE

This document describes the steps required to fully set up the development environment.

For details on deploying the application, refer to [MINE deployment](./documentation/deployment/README.md).

**Table of Contents**

- [Environment setup](#environment-setup)
  - [Install tools](#install-tools)
  - [Install external packages](#install-external-packages)
  - [Install and configure local database](#install-and-configure-local-database)
- [MINE architecture overview](#mine-architecture-overview)
- [MINE Service](#mine-service)
  - [Running the service](#running-the-service)
  - [API Documentation](#api-documentation)
- [MINE UI](#mine-ui)
  - [Running the ui](#running-the-ui)
- [Development procedures, practices, and guidelines](#development-procedures-practices-and-guidelines)

## Environment setup

### Install tools

#### `VSCode and Extensions`

Download VSCode from https://code.visualstudio.com/Download and install.

When opening the repository in VSCode, look for a notification in the bottom
right of the app that asks to install all recommended workplace extensions.
Choose the install option.

#### `Node.js and NPM`

Download and install [Node.js](https://nodejs.org/en). This will include NPM. **Must have at least Node 15** in order to get a NPM 7 (minimum) that supports workspaces (which we need).

#### `Nest.js CLI`

From the **packages/mine-service** folder, run:

```
npm i -g @nestjs/cli
```

### Install external packages

After cloning the repository, execute the following from the repository _root_ folder:

```
npm install
if you encounter error due to dependency just add --legacy-peer-deps

```

### Install and configure local database

For local development, you'll need to install and configure a local instance of MongoDB.

#### `Install MongoDB`

1. Download and run installer from https://www.mongodb.com/try/download/community
1. Choose "Complete" install.
1. Run as Network Service user.
1. Check "Install Mongo Compass".

#### `Set up test database`

1. Run MongoDb Compass.
1. Save and connect to default -- mongodb://localhost:27017
1. Name: **MINE**
1. Create a new database named **mine**.
1. Create the following collections in the **mine** database and use **Add Data > Import JSON or CSV** to import the indicated JSON file:

   | Collection   | JSON                                            |
   | ------------ | ----------------------------------------------- |
   | **projects** | **apps\mine-service\data\miningHardwares.json** |
   | **users**    | **apps\mine-service\data\users.json**           |

---

## MINE architecture overview

The MINE is composed of the following processes:

- MINE UI - front-end web application
- MINE Service - back-end web service

The MINE UI makes HTTP requests to the MINE Service for data access and external API requests.

---

## MINE UI

The MINE UI is an application using react js framework

### Running the ui

From the repository _root_, you can start the service with either of the following commands:

| Command            | Description |
| ------------------ | ----------- |
| `npm run ui:start` | Run ui      |

To verify that the service is running, access the following URL in your browser:
http://localhost:4200/. If working, the browser should display the ui page

You can also run the ui using NX console > serve > mine-ui

---

## MINE Service

The MINE Service is a Node.js service implemented using the [Nest.js framework](https://docs.nestjs.com/) on top of Express.

### Running the service

From the repository _root_, you can start the service with either of the following commands:

| Command                 | Description         |
| ----------------------- | ------------------- |
| `npm run service:start` | Run service (watch) |

To verify that the service is running, access the following URL in your browser:
http://localhost:3000/health/hello. If working, the browser should display the following:

> Hello MINE!

### API Documentation

API documentation by Swagger: http://localhost:3000/api-docs

---

## Development procedures, practices, and guidelines

Refer to [Development procedures, practices, and guidelines](./documentation/development/README.md) for detailed development procedures and guidelines.
