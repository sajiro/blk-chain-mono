/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ([
/* 0 */,
/* 1 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.bootstrap = void 0;
const tslib_1 = __webpack_require__(2);
const cookie_parser_1 = tslib_1.__importDefault(__webpack_require__(3));
const core_1 = __webpack_require__(4);
const swagger_1 = __webpack_require__(5);
const app_module_1 = __webpack_require__(6);
const common_1 = __webpack_require__(7);
const nest_winston_1 = __webpack_require__(121);
const fs_1 = __webpack_require__(141);
const assert_is_truthy_1 = __webpack_require__(40);
const env_helper_1 = __webpack_require__(142);
function bootstrap() {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const app = yield createApp();
        app.useLogger(app.get(nest_winston_1.WINSTON_MODULE_NEST_PROVIDER));
        const config = new swagger_1.DocumentBuilder()
            .setTitle('Orbital HRMS -- API Documentation')
            .setDescription('API documentation for Orbital HRMS')
            .setVersion('1.0')
            .addTag('hrms')
            .addBearerAuth()
            .build();
        const document = swagger_1.SwaggerModule.createDocument(app, config);
        swagger_1.SwaggerModule.setup('api-docs', app, document);
        app.enableCors();
        app.use((0, cookie_parser_1.default)());
        app.useGlobalPipes(new common_1.ValidationPipe());
        const port = (0, env_helper_1.getIntegerEnvironmentVariable)('PORT', 3000);
        yield app.listen(port);
    });
}
exports.bootstrap = bootstrap;
const createApp = () => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    const useHttps = (0, env_helper_1.getBooleanEnvironmentVariable)('USE_HTTPS');
    if (useHttps) {
        const keyFile = (0, env_helper_1.getStringEnvironmentVariable)('HTTPS_KEY_FILE');
        (0, assert_is_truthy_1.assertIsTruthy)(keyFile, 'HTTPS_KEY_FILE variable not defined');
        const certFile = (0, env_helper_1.getStringEnvironmentVariable)('HTTPS_CERT_FILE');
        (0, assert_is_truthy_1.assertIsTruthy)(certFile, 'HTTPS_CERT_FILE variable not defined');
        const httpsOptions = {
            key: (0, fs_1.readFileSync)(keyFile),
            cert: (0, fs_1.readFileSync)(certFile),
        };
        const applicationOptions = {
            bufferLogs: true,
            httpsOptions,
        };
        return yield core_1.NestFactory.create(app_module_1.AppModule, applicationOptions);
    }
    return yield core_1.NestFactory.create(app_module_1.AppModule, {
        bufferLogs: true,
    });
});


/***/ }),
/* 2 */
/***/ ((module) => {

module.exports = require("tslib");

/***/ }),
/* 3 */
/***/ ((module) => {

module.exports = require("cookie-parser");

/***/ }),
/* 4 */
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),
/* 5 */
/***/ ((module) => {

module.exports = require("@nestjs/swagger");

/***/ }),
/* 6 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const config_1 = __webpack_require__(9);
const auth_module_1 = __webpack_require__(10);
const users_module_1 = __webpack_require__(46);
const health_module_1 = __webpack_require__(87);
const load_config_1 = __webpack_require__(90);
const mongoose_config_service_1 = __webpack_require__(91);
const user_module_1 = __webpack_require__(92);
const logger_middleware_1 = __webpack_require__(120);
const nest_winston_1 = __webpack_require__(121);
const winston_config_service_1 = __webpack_require__(122);
const clients_module_1 = __webpack_require__(71);
const projects_module_1 = __webpack_require__(63);
const activities_module_1 = __webpack_require__(79);
const reports_module_1 = __webpack_require__(126);
const feature_flags_module_1 = __webpack_require__(131);
let AppModule = class AppModule {
    configure(consumer) {
        consumer.apply(logger_middleware_1.LoggerMiddleware).forRoutes('*');
    }
};
AppModule = tslib_1.__decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({ isGlobal: true, load: [load_config_1.loadConfig], cache: true }),
            nest_winston_1.WinstonModule.forRootAsync({ useClass: winston_config_service_1.WinstonConfigService }),
            mongoose_1.MongooseModule.forRootAsync({
                useClass: mongoose_config_service_1.MongooseConfigService,
            }),
            activities_module_1.ActivitiesModule,
            auth_module_1.AuthModule,
            clients_module_1.ClientsModule,
            feature_flags_module_1.FeatureFlagsModule,
            health_module_1.HealthModule,
            projects_module_1.ProjectsModule,
            reports_module_1.ReportsModule,
            user_module_1.UserModule,
            users_module_1.UsersModule,
        ],
    })
], AppModule);
exports.AppModule = AppModule;


/***/ }),
/* 7 */
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),
/* 8 */
/***/ ((module) => {

module.exports = require("@nestjs/mongoose");

/***/ }),
/* 9 */
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),
/* 10 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
const core_1 = __webpack_require__(4);
const jwt_1 = __webpack_require__(11);
const mongoose_1 = __webpack_require__(8);
const access_token_schema_1 = __webpack_require__(12);
const auth_service_1 = __webpack_require__(13);
const auth_controller_1 = __webpack_require__(35);
const auth_guard_1 = __webpack_require__(41);
const jwt_config_helper_1 = __webpack_require__(45);
const user_schema_1 = __webpack_require__(16);
let AuthModule = class AuthModule {
};
AuthModule = tslib_1.__decorate([
    (0, common_1.Module)({
        imports: [
            jwt_1.JwtModule.registerAsync({
                inject: [config_1.ConfigService],
                useFactory: jwt_config_helper_1.configJwtModule,
            }),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: access_token_schema_1.AccessTokenRecord.name,
                    schema: access_token_schema_1.AccessTokenSchema,
                },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: user_schema_1.UserRecord.name,
                    schema: user_schema_1.UserSchema,
                },
            ]),
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [
            auth_service_1.AuthService,
            {
                provide: core_1.APP_GUARD,
                useClass: auth_guard_1.AuthGuard,
            },
        ],
        exports: [auth_service_1.AuthService],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),
/* 11 */
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),
/* 12 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AccessTokenSchema = exports.AccessTokenRecord = void 0;
const tslib_1 = __webpack_require__(2);
const mongoose_1 = __webpack_require__(8);
const swagger_1 = __webpack_require__(5);
let AccessTokenRecord = class AccessTokenRecord {
};
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], AccessTokenRecord.prototype, "token", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], AccessTokenRecord.prototype, "userEmail", void 0);
AccessTokenRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'accessTokens' })
], AccessTokenRecord);
exports.AccessTokenRecord = AccessTokenRecord;
const AccessTokenSchema = mongoose_1.SchemaFactory.createForClass(AccessTokenRecord);
exports.AccessTokenSchema = AccessTokenSchema;


/***/ }),
/* 13 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
const jwt_1 = __webpack_require__(11);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const bcrypt = tslib_1.__importStar(__webpack_require__(15));
const access_token_schema_1 = __webpack_require__(12);
const user_schema_1 = __webpack_require__(16);
const api_helper_1 = __webpack_require__(31);
const assert_user_exists_1 = __webpack_require__(32);
const assert_user_role_is_admin_1 = __webpack_require__(34);
let AuthService = class AuthService {
    constructor(jwtService, configService, accessTokenModel, userModel) {
        this.jwtService = jwtService;
        this.configService = configService;
        this.accessTokenModel = accessTokenModel;
        this.userModel = userModel;
    }
    signIn(email, password) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const user = yield this.userModel.findOne({
                email: email.toLowerCase(),
                status: 'enabled',
            });
            if (!user) {
                return undefined;
            }
            try {
                if (yield bcrypt.compare(password, user.passwordHash)) {
                    const payload = {
                        username: user.email,
                        sub: user._id.toString(),
                    };
                    const accessToken = yield this.jwtService.signAsync(payload);
                    this.saveOneToken(accessToken, email);
                    const expiresInSeconds = parseInt(this.configService.get('jwtRefreshExpiresInMinutes', {
                        infer: true,
                    })) * 60;
                    const refreshToken = yield this.jwtService.signAsync(payload, {
                        secret: this.configService.get('jwtRefreshSecret', { infer: true }),
                        expiresIn: expiresInSeconds,
                    });
                    const tokens = {
                        accessToken,
                        refreshToken,
                    };
                    return tokens;
                }
                return undefined;
            }
            catch (_a) {
                return undefined;
            }
        });
    }
    refresh(refreshToken) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            let accessToken;
            try {
                const refreshPayload = yield this.jwtService.verifyAsync(refreshToken, {
                    secret: this.configService.get('jwtRefreshSecret', { infer: true }),
                });
                const accessPayload = {
                    username: refreshPayload.username,
                    sub: refreshPayload.sub,
                };
                const expiresInSeconds = parseInt(this.configService.get('jwtAccessExpiresInMinutes', { infer: true })) * 60;
                accessToken = yield this.jwtService.signAsync(accessPayload, {
                    secret: this.configService.get('jwtAccessSecret', { infer: true }),
                    expiresIn: expiresInSeconds,
                });
                this.saveOneToken(accessToken, accessPayload.username);
            }
            catch (error) {
                return undefined;
            }
            return accessToken;
        });
    }
    signOut(token) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const tokenDoc = yield this.findTokenInWhiteList(token);
            if (!tokenDoc) {
                return undefined;
            }
            try {
                yield this.deleteTokenFromWhiteList(token);
            }
            catch (_a) {
                return undefined;
            }
            return tokenDoc;
        });
    }
    findTokenInWhiteList(token) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            try {
                const tokenDoc = yield this.accessTokenModel.findOne({ token }).exec();
                return tokenDoc !== null && tokenDoc !== void 0 ? tokenDoc : undefined;
            }
            catch (_a) {
                return undefined;
            }
        });
    }
    deleteTokenFromWhiteList(token) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.accessTokenModel.deleteMany({ token }).exec();
        });
    }
    ensureCurrentUserIsAdmin(request) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const currentUserId = (0, api_helper_1.getCurrentUserId)(request);
            const currentUserRecord = yield this.userModel.findById(currentUserId);
            (0, assert_user_exists_1.assertUserExists)(currentUserRecord, currentUserId);
            (0, assert_user_role_is_admin_1.assertUserRoleIsAdmin)(currentUserRecord.role);
            return currentUserRecord;
        });
    }
    saveOneToken(accessToken, email) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const tokenDoc = {
                token: accessToken,
                userEmail: email,
            };
            // store at most one access token for each user email
            yield this.accessTokenModel.deleteMany({ userEmail: email }).exec();
            yield this.accessTokenModel.create(tokenDoc);
        });
    }
};
AuthService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(2, (0, mongoose_1.InjectModel)(access_token_schema_1.AccessTokenRecord.name)),
    tslib_1.__param(3, (0, mongoose_1.InjectModel)(user_schema_1.UserRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object, typeof (_c = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _c : Object, typeof (_d = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _d : Object])
], AuthService);
exports.AuthService = AuthService;


/***/ }),
/* 14 */
/***/ ((module) => {

module.exports = require("mongoose");

/***/ }),
/* 15 */
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),
/* 16 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserSchema = exports.UserRecord = void 0;
const tslib_1 = __webpack_require__(2);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const bcrypt = tslib_1.__importStar(__webpack_require__(15));
const models_1 = __webpack_require__(17);
const activity_schema_1 = __webpack_require__(28);
const project_schema_1 = __webpack_require__(30);
const client_schema_1 = __webpack_require__(29);
let UserRecord = class UserRecord {
};
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], UserRecord.prototype, "firstName", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], UserRecord.prototype, "lastName", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], UserRecord.prototype, "email", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true, default: 'member', type: String }),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.UserRole !== "undefined" && models_1.UserRole) === "function" ? _a : Object)
], UserRecord.prototype, "role", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true, default: 'enabled', type: String }),
    tslib_1.__metadata("design:type", typeof (_b = typeof models_1.UserStatus !== "undefined" && models_1.UserStatus) === "function" ? _b : Object)
], UserRecord.prototype, "status", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)(),
    tslib_1.__metadata("design:type", String)
], UserRecord.prototype, "passwordHash", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)([{ type: mongoose_2.SchemaTypes.ObjectId, ref: client_schema_1.ClientRecord.name }]),
    tslib_1.__metadata("design:type", Array)
], UserRecord.prototype, "clients", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)([{ type: mongoose_2.SchemaTypes.ObjectId, ref: project_schema_1.ProjectRecord.name }]),
    tslib_1.__metadata("design:type", Array)
], UserRecord.prototype, "projects", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)([{ type: mongoose_2.SchemaTypes.ObjectId, ref: activity_schema_1.ActivityRecord.name }]),
    tslib_1.__metadata("design:type", Array)
], UserRecord.prototype, "activities", void 0);
UserRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'users' })
], UserRecord);
exports.UserRecord = UserRecord;
const UserSchema = mongoose_1.SchemaFactory.createForClass(UserRecord);
exports.UserSchema = UserSchema;
UserSchema.pre('save', function (next) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!this.isModified('password'))
            return next();
        this.passwordHash = yield bcrypt.hash(this.passwordHash, 10);
        next();
    });
});


/***/ }),
/* 17 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(2);
tslib_1.__exportStar(__webpack_require__(18), exports);
tslib_1.__exportStar(__webpack_require__(19), exports);
tslib_1.__exportStar(__webpack_require__(20), exports);
tslib_1.__exportStar(__webpack_require__(21), exports);
tslib_1.__exportStar(__webpack_require__(22), exports);
tslib_1.__exportStar(__webpack_require__(23), exports);
tslib_1.__exportStar(__webpack_require__(24), exports);
tslib_1.__exportStar(__webpack_require__(25), exports);
tslib_1.__exportStar(__webpack_require__(26), exports);
tslib_1.__exportStar(__webpack_require__(27), exports);


/***/ }),
/* 18 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.activityStatusList = void 0;
exports.activityStatusList = ['enabled', 'disabled'];


/***/ }),
/* 19 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.clientContactMethodList = exports.clientStatusList = void 0;
exports.clientStatusList = ['active', 'inactive'];
exports.clientContactMethodList = ['email', 'phone'];


/***/ }),
/* 20 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.environmentTypeList = void 0;
exports.environmentTypeList = ['dev', 'test', 'prod'];


/***/ }),
/* 21 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 22 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 23 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.projectStatusList = void 0;
exports.projectStatusList = ['active', 'inactive'];


/***/ }),
/* 24 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.timesheetEventTypeList = void 0;
exports.timesheetEventTypeList = ['work', 'sick', 'vacation'];


/***/ }),
/* 25 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 26 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.User = exports.AssignedActivity = exports.AssignedProject = exports.AssignedClient = exports.userStatusList = exports.userRoleList = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const organization_1 = __webpack_require__(22);
exports.userRoleList = ['admin', 'member'];
exports.userStatusList = ['enabled', 'disabled'];
// TODO: Define interface here and remove NestJs decorators (shouldn't be
// in code used directly in UI)
class AssignedClient {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedClient.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedClient.prototype, "name", void 0);
exports.AssignedClient = AssignedClient;
class AssignedProject {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedProject.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedProject.prototype, "name", void 0);
exports.AssignedProject = AssignedProject;
class AssignedActivity {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedActivity.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedActivity.prototype, "name", void 0);
exports.AssignedActivity = AssignedActivity;
class User {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], User.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], User.prototype, "firstName", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], User.prototype, "lastName", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], User.prototype, "email", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: ['admin', 'manager', 'member'],
        example: 'member',
    }),
    tslib_1.__metadata("design:type", typeof (_a = typeof UserRole !== "undefined" && UserRole) === "function" ? _a : Object)
], User.prototype, "role", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: ['enabled', 'disabled'],
        example: 'enabled',
    }),
    tslib_1.__metadata("design:type", typeof (_b = typeof UserStatus !== "undefined" && UserStatus) === "function" ? _b : Object)
], User.prototype, "status", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", typeof (_c = typeof organization_1.IOrganization !== "undefined" && organization_1.IOrganization) === "function" ? _c : Object)
], User.prototype, "organization", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ type: AssignedClient, isArray: true }),
    tslib_1.__metadata("design:type", Array)
], User.prototype, "clients", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ type: AssignedProject, isArray: true }),
    tslib_1.__metadata("design:type", Array)
], User.prototype, "projects", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ type: AssignedActivity, isArray: true }),
    tslib_1.__metadata("design:type", Array)
], User.prototype, "activities", void 0);
exports.User = User;


/***/ }),
/* 27 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 28 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ActivitySchema = exports.ActivityRecord = void 0;
const tslib_1 = __webpack_require__(2);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const client_schema_1 = __webpack_require__(29);
const project_schema_1 = __webpack_require__(30);
const models_1 = __webpack_require__(17);
let ActivityRecord = class ActivityRecord {
};
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.SchemaTypes.ObjectId, ref: client_schema_1.ClientRecord.name, required: true }),
    tslib_1.__metadata("design:type", typeof (_a = typeof client_schema_1.ClientRecord !== "undefined" && client_schema_1.ClientRecord) === "function" ? _a : Object)
], ActivityRecord.prototype, "client", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.SchemaTypes.ObjectId, ref: project_schema_1.ProjectRecord.name, required: true }),
    tslib_1.__metadata("design:type", typeof (_b = typeof project_schema_1.ProjectRecord !== "undefined" && project_schema_1.ProjectRecord) === "function" ? _b : Object)
], ActivityRecord.prototype, "project", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], ActivityRecord.prototype, "name", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true, default: 'enabled', type: String }),
    tslib_1.__metadata("design:type", typeof (_c = typeof models_1.ActivityStatus !== "undefined" && models_1.ActivityStatus) === "function" ? _c : Object)
], ActivityRecord.prototype, "status", void 0);
ActivityRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'activities' })
], ActivityRecord);
exports.ActivityRecord = ActivityRecord;
const ActivitySchema = mongoose_1.SchemaFactory.createForClass(ActivityRecord);
exports.ActivitySchema = ActivitySchema;


/***/ }),
/* 29 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ClientSchema = exports.ClientRecord = void 0;
const tslib_1 = __webpack_require__(2);
const models_1 = __webpack_require__(17);
const mongoose_1 = __webpack_require__(8);
let ClientRecord = class ClientRecord {
};
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], ClientRecord.prototype, "name", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true, default: 'active', type: String }),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ClientStatus !== "undefined" && models_1.ClientStatus) === "function" ? _a : Object)
], ClientRecord.prototype, "status", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: false }),
    tslib_1.__metadata("design:type", String)
], ClientRecord.prototype, "contactName", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: false }),
    tslib_1.__metadata("design:type", String)
], ClientRecord.prototype, "contactEmail", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: false }),
    tslib_1.__metadata("design:type", String)
], ClientRecord.prototype, "contactPhone", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: false, default: 'email', type: String }),
    tslib_1.__metadata("design:type", typeof (_b = typeof models_1.ClientContactMethod !== "undefined" && models_1.ClientContactMethod) === "function" ? _b : Object)
], ClientRecord.prototype, "contactMethod", void 0);
ClientRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'clients' })
], ClientRecord);
exports.ClientRecord = ClientRecord;
const ClientSchema = mongoose_1.SchemaFactory.createForClass(ClientRecord);
exports.ClientSchema = ClientSchema;


/***/ }),
/* 30 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProjectSchema = exports.ProjectRecord = void 0;
const tslib_1 = __webpack_require__(2);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const client_schema_1 = __webpack_require__(29);
const models_1 = __webpack_require__(17);
let ProjectRecord = class ProjectRecord {
};
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.SchemaTypes.ObjectId, ref: client_schema_1.ClientRecord.name, required: true }),
    tslib_1.__metadata("design:type", typeof (_a = typeof client_schema_1.ClientRecord !== "undefined" && client_schema_1.ClientRecord) === "function" ? _a : Object)
], ProjectRecord.prototype, "client", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], ProjectRecord.prototype, "name", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true, default: 'active', type: String }),
    tslib_1.__metadata("design:type", typeof (_b = typeof models_1.ProjectStatus !== "undefined" && models_1.ProjectStatus) === "function" ? _b : Object)
], ProjectRecord.prototype, "status", void 0);
ProjectRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'projects' })
], ProjectRecord);
exports.ProjectRecord = ProjectRecord;
const ProjectSchema = mongoose_1.SchemaFactory.createForClass(ProjectRecord);
exports.ProjectSchema = ProjectSchema;


/***/ }),
/* 31 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getCurrentUserId = void 0;
const getCurrentUserId = (request) => {
    const decodedToken = request['user'];
    return decodedToken.sub;
};
exports.getCurrentUserId = getCurrentUserId;


/***/ }),
/* 32 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.assertUserExists = void 0;
const assert_is_defined_1 = __webpack_require__(33);
function assertUserExists(user, userId) {
    (0, assert_is_defined_1.assertIsDefined)(user, `User for id ${userId} not found`);
}
exports.assertUserExists = assertUserExists;


/***/ }),
/* 33 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.assertIsDefined = void 0;
const common_1 = __webpack_require__(7);
function assertIsDefined(value, errorMessage = 'Value is not defined') {
    if (value === undefined || value === null) {
        throw new common_1.InternalServerErrorException(errorMessage);
    }
}
exports.assertIsDefined = assertIsDefined;


/***/ }),
/* 34 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.assertUserRoleIsAdmin = void 0;
const common_1 = __webpack_require__(7);
function assertUserRoleIsAdmin(userRole) {
    const errorMessage = "User's role is not 'admin'";
    if (userRole !== 'admin') {
        throw new common_1.ForbiddenException(errorMessage);
    }
}
exports.assertUserRoleIsAdmin = assertUserRoleIsAdmin;


/***/ }),
/* 35 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
const swagger_1 = __webpack_require__(5);
const express_1 = __webpack_require__(36);
const auth_service_1 = __webpack_require__(13);
const auth_dto_1 = __webpack_require__(37);
const skip_auth_decorator_1 = __webpack_require__(38);
const auth_helper_1 = __webpack_require__(39);
const assert_is_truthy_1 = __webpack_require__(40);
let AuthController = class AuthController {
    constructor(authService, configService) {
        this.authService = authService;
        this.configService = configService;
    }
    signIn(signInDto, res) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const authTokens = yield this.authService.signIn(signInDto.email, signInDto.password);
            if (!authTokens) {
                throw new common_1.UnauthorizedException();
            }
            const useHttps = this.configService.get('useHttps', { infer: true });
            const expiresInMilliseconds = parseInt(this.configService.get('jwtRefreshExpiresInMinutes', { infer: true })) *
                60 *
                1000;
            res.cookie(auth_helper_1.refreshTokenCookieName, authTokens.refreshToken, {
                httpOnly: true,
                sameSite: 'none',
                secure: useHttps,
                maxAge: expiresInMilliseconds,
            });
            return res.json({ accessToken: authTokens.accessToken });
        });
    }
    refresh(request, res) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const refreshToken = request.cookies[auth_helper_1.refreshTokenCookieName];
            if (!refreshToken) {
                throw new common_1.UnauthorizedException();
            }
            const accessToken = yield this.authService.refresh(refreshToken);
            if (!accessToken) {
                throw new common_1.UnauthorizedException();
            }
            return res.json({ accessToken });
        });
    }
    signOut(request) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const token = (0, auth_helper_1.extractTokenFromHeader)(request);
            (0, assert_is_truthy_1.assertIsTruthy)(token, 'Authentication token not found');
            const deletedTokenDoc = yield this.authService.signOut(token);
            if (!deletedTokenDoc) {
                throw new common_1.InternalServerErrorException('Unable to delete token');
            }
        });
    }
};
tslib_1.__decorate([
    (0, swagger_1.ApiBody)({ type: auth_dto_1.SignInDto }),
    (0, swagger_1.ApiOkResponse)({
        description: 'Successful login. Sends refresh token in http-only cookie "jwt_refresh_token" to the front-end.',
        type: auth_dto_1.AccessTokenDto,
    }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, skip_auth_decorator_1.SkipAuth)(),
    (0, common_1.Post)('login'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    tslib_1.__param(0, (0, common_1.Body)()),
    tslib_1.__param(1, (0, common_1.Res)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_c = typeof auth_dto_1.SignInDto !== "undefined" && auth_dto_1.SignInDto) === "function" ? _c : Object, typeof (_d = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _d : Object]),
    tslib_1.__metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], AuthController.prototype, "signIn", null);
tslib_1.__decorate([
    (0, swagger_1.ApiOkResponse)({
        description: 'Successful refresh',
        type: auth_dto_1.AccessTokenDto,
    }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, skip_auth_decorator_1.SkipAuth)(),
    (0, common_1.Post)('refresh'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Res)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_f = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _f : Object, typeof (_g = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _g : Object]),
    tslib_1.__metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
], AuthController.prototype, "refresh", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'Successful logout' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Post)('logout'),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_j = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _j : Object]),
    tslib_1.__metadata("design:returntype", typeof (_k = typeof Promise !== "undefined" && Promise) === "function" ? _k : Object)
], AuthController.prototype, "signOut", null);
AuthController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Authentication'),
    (0, common_1.Controller)('auth'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object])
], AuthController);
exports.AuthController = AuthController;


/***/ }),
/* 36 */
/***/ ((module) => {

module.exports = require("express");

/***/ }),
/* 37 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AccessTokenDto = exports.SignInDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
class SignInDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], SignInDto.prototype, "email", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], SignInDto.prototype, "password", void 0);
exports.SignInDto = SignInDto;
class AccessTokenDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AccessTokenDto.prototype, "accessToken", void 0);
exports.AccessTokenDto = AccessTokenDto;


/***/ }),
/* 38 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SkipAuth = exports.SKIP_AUTH_KEY = void 0;
const common_1 = __webpack_require__(7);
exports.SKIP_AUTH_KEY = 'skipAuth';
const SkipAuth = () => (0, common_1.SetMetadata)(exports.SKIP_AUTH_KEY, true);
exports.SkipAuth = SkipAuth;


/***/ }),
/* 39 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.extractTokenFromHeader = exports.refreshTokenCookieName = void 0;
exports.refreshTokenCookieName = 'jwt_refresh_token';
const extractTokenFromHeader = (request) => {
    var _a, _b;
    const [type, token] = (_b = (_a = request.headers.authorization) === null || _a === void 0 ? void 0 : _a.split(' ')) !== null && _b !== void 0 ? _b : [];
    return type === 'Bearer' ? token : undefined;
};
exports.extractTokenFromHeader = extractTokenFromHeader;


/***/ }),
/* 40 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.assertIsTruthy = void 0;
const common_1 = __webpack_require__(7);
function assertIsTruthy(value, errorMessage = 'Value is falsy') {
    if (!value) {
        throw new common_1.InternalServerErrorException(errorMessage);
    }
}
exports.assertIsTruthy = assertIsTruthy;


/***/ }),
/* 41 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthGuard = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
const core_1 = __webpack_require__(4);
const jwt_1 = __webpack_require__(11);
const datetime_1 = __webpack_require__(42);
const skip_auth_decorator_1 = __webpack_require__(38);
const auth_helper_1 = __webpack_require__(39);
const auth_service_1 = __webpack_require__(13);
let AuthGuard = class AuthGuard {
    constructor(authService, configService, jwtService, reflector) {
        this.authService = authService;
        this.configService = configService;
        this.jwtService = jwtService;
        this.reflector = reflector;
    }
    canActivate(context) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const skipAuth = this.reflector.getAllAndOverride(skip_auth_decorator_1.SKIP_AUTH_KEY, [
                context.getHandler(),
                context.getClass(),
            ]);
            if (skipAuth) {
                return true;
            }
            const request = context.switchToHttp().getRequest();
            const token = (0, auth_helper_1.extractTokenFromHeader)(request);
            if (!token) {
                throw new common_1.UnauthorizedException();
            }
            let payload;
            try {
                const decoded = this.jwtService.decode(token);
                if ((0, datetime_1.getNewDate)().getTime() > decoded.exp * 1000) {
                    this.authService.deleteTokenFromWhiteList(token);
                    throw new common_1.UnauthorizedException();
                }
                payload = yield this.jwtService.verifyAsync(token, {
                    secret: this.configService.get('jwtAccessSecret', { infer: true }),
                });
            }
            catch (_a) {
                throw new common_1.UnauthorizedException();
            }
            const tokenDoc = yield this.authService.findTokenInWhiteList(token);
            if (!tokenDoc) {
                throw new common_1.UnauthorizedException();
            }
            // 💡 We're assigning the payload to the request object here
            // so that we can access it in our route handlers
            request['user'] = payload;
            return true;
        });
    }
};
AuthGuard = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object, typeof (_c = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _c : Object, typeof (_d = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _d : Object])
], AuthGuard);
exports.AuthGuard = AuthGuard;


/***/ }),
/* 42 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(2);
tslib_1.__exportStar(__webpack_require__(43), exports);


/***/ }),
/* 43 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.dateToISODateString = exports.isoDateStringToLocalDate = exports.formatMinutesAsTime = exports.formatEventTime = exports.roundEventTime = exports.parseEventTimeString = exports.convertTimeInputString = exports.timeInputRegex = exports.convertHoursToMinutes = exports.convertMinutesToHours = exports.getDateForWeekday = exports.getNewDate = exports.weekdayStrings = void 0;
const tslib_1 = __webpack_require__(2);
const dayjs_1 = tslib_1.__importDefault(__webpack_require__(44));
exports.weekdayStrings = [
    'monday',
    'tuesday',
    'wednesday',
    'thursday',
    'friday',
    'saturday',
    'sunday',
];
const getNewDate = () => new Date();
exports.getNewDate = getNewDate;
/**************
 * Get the date of a weekday (Monday = 1 ... Sunday = 7)
 * in a given week, which is the Monday-to-Sunday containing refDate
 */
const getDateForWeekday = (weekday, refDate) => {
    const refDay = (0, dayjs_1.default)(refDate);
    const startSunday = refDay.day() === 0 ? refDay.subtract(7, 'day') : refDay.startOf('week');
    const dateDiff = typeof weekday === 'number' ? weekday : exports.weekdayStrings.indexOf(weekday) + 1;
    const thisDay = startSunday.add(dateDiff, 'day');
    const thisDate = thisDay.toDate();
    return thisDate;
};
exports.getDateForWeekday = getDateForWeekday;
// convert minutes (integers) to hours (2-decimal)
const convertMinutesToHours = (minutes) => {
    const hours = minutes / 60;
    const roundedHours = Math.round(hours * 100) / 100;
    return roundedHours;
};
exports.convertMinutesToHours = convertMinutesToHours;
// convert hours (2-decimal) to minutes (integers)
const convertHoursToMinutes = (hours) => {
    const hours24 = Math.min(Math.max(hours, 0), 24);
    const minutes = Math.round(hours24 * 60);
    return minutes;
};
exports.convertHoursToMinutes = convertHoursToMinutes;
exports.timeInputRegex = /^[0-9]{0,2}([.:][0-9]{0,2})?$/;
const convertTimeInputString = (inputString) => {
    let value = 0;
    if (inputString) {
        const inputValue = inputString.includes(':')
            ? (0, exports.parseEventTimeString)(inputString)
            : Number.parseFloat(inputString);
        if (inputValue < 0) {
            value = 0;
        }
        else if (inputValue > 24) {
            value = 24;
        }
        else {
            value = (0, exports.roundEventTime)(inputValue);
        }
    }
    return value;
};
exports.convertTimeInputString = convertTimeInputString;
// parse event time from 'hh:mm' string to decimal number
const parseEventTimeString = (timeString) => {
    if (!timeString.includes(':')) {
        throw new Error(`An error occurred: timeString '${timeString}' is missing a colon`);
    }
    const timeArray = timeString.split(':');
    const firstString = timeArray[0] || '0';
    const secondString = timeArray[1] || '0';
    const hours = Number.parseInt(firstString);
    const minutes = Number.parseInt(secondString);
    const eventTime = hours + (0, exports.convertMinutesToHours)(minutes);
    return eventTime;
};
exports.parseEventTimeString = parseEventTimeString;
/**************
  In some cases, converting hours (2-decimal) to minutes (integers)
  then back to hours results in a different number.
    eg: 0.14 hours => 8 minutes => 0.13 hour
  
  This is the inevitable result of our event time rounding rules.

  We use the roundEventTime() function below to adjust the number right after
  the user enters event time (hours) in WorkInput and EventTypePopover,
  so that they know what's happening.
*/
const roundEventTime = (hours) => {
    const minutes = (0, exports.convertHoursToMinutes)(hours);
    const result = (0, exports.convertMinutesToHours)(minutes);
    return result;
};
exports.roundEventTime = roundEventTime;
const formatEventTime = (eventHours) => {
    const hours = Math.floor(eventHours);
    const minutes = Math.round((eventHours - hours) * 60);
    const minutesString = minutes < 10 ? `0${minutes}` : `${minutes}`;
    return `${hours}:${minutesString}`;
};
exports.formatEventTime = formatEventTime;
const formatMinutesAsTime = (minutes) => {
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    return `${hours}:${remainingMinutes < 10 ? `0${remainingMinutes}` : remainingMinutes}`;
};
exports.formatMinutesAsTime = formatMinutesAsTime;
const isoDateStringToLocalDate = (isoDateString) => new Date(`${isoDateString}T00:00:00`);
exports.isoDateStringToLocalDate = isoDateStringToLocalDate;
const dateToISODateString = (date) => date.toISOString().split('T')[0];
exports.dateToISODateString = dateToISODateString;


/***/ }),
/* 44 */
/***/ ((module) => {

module.exports = require("dayjs");

/***/ }),
/* 45 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.configJwtModule = void 0;
const configJwtModule = (configService) => {
    const expiresInSeconds = parseInt(configService.get('jwtAccessExpiresInMinutes', { infer: true })) *
        60;
    return {
        global: true,
        secret: configService.get('jwtAccessSecret', { infer: true }),
        signOptions: {
            expiresIn: expiresInSeconds,
        },
    };
};
exports.configJwtModule = configJwtModule;


/***/ }),
/* 46 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const user_schema_1 = __webpack_require__(16);
const users_controller_1 = __webpack_require__(47);
const users_service_1 = __webpack_require__(48);
const users_assembler_1 = __webpack_require__(54);
const user_record_helper_1 = __webpack_require__(62);
const auth_module_1 = __webpack_require__(10);
const projects_module_1 = __webpack_require__(63);
const activities_module_1 = __webpack_require__(79);
let UsersModule = class UsersModule {
};
UsersModule = tslib_1.__decorate([
    (0, common_1.Module)({
        exports: [users_service_1.UsersService],
        controllers: [users_controller_1.UsersController],
        providers: [users_service_1.UsersService, users_assembler_1.UsersAssembler, user_record_helper_1.UserRecordHelper],
        imports: [
            mongoose_1.MongooseModule.forFeature([{ name: user_schema_1.UserRecord.name, schema: user_schema_1.UserSchema }]),
            auth_module_1.AuthModule,
            projects_module_1.ProjectsModule,
            activities_module_1.ActivitiesModule,
        ],
    })
], UsersModule);
exports.UsersModule = UsersModule;


/***/ }),
/* 47 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t, _u, _v, _w, _x, _y;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const users_service_1 = __webpack_require__(48);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
const users_assembler_1 = __webpack_require__(54);
const get_user_params_1 = __webpack_require__(55);
const create_user_dto_1 = __webpack_require__(57);
const update_user_status_dto_1 = __webpack_require__(59);
const update_user_password_dto_1 = __webpack_require__(60);
const update_user_activities_dto_1 = __webpack_require__(61);
const auth_service_1 = __webpack_require__(13);
let UsersController = class UsersController {
    constructor(usersService, usersAssembler, authService) {
        this.usersService = usersService;
        this.usersAssembler = usersAssembler;
        this.authService = authService;
    }
    getUsers(request) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            const userRecords = yield this.usersService.findAll();
            return userRecords.map((userRecord) => this.usersAssembler.assembleUser(userRecord));
        });
    }
    getUserById(request, { userId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            const userRecord = yield this.usersService.findById(userId);
            if (!userRecord) {
                throw new common_1.NotFoundException();
            }
            return this.usersAssembler.assembleUser(userRecord);
        });
    }
    createUser(request, createUserDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            const id = yield this.usersService.createUser(createUserDto);
            return { id };
        });
    }
    updateUserStatus(request, { userId }, { status }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.usersService.updateUserStatus(userId, status);
        });
    }
    updateUserPassword(request, { userId }, { password }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.usersService.updateUserPassword(userId, password);
        });
    }
    updateUserActivities(request, { userId }, { projectId, activityIds }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.usersService.updateUserActivities(userId, projectId, activityIds);
        });
    }
};
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({
        description: 'Success',
        type: models_1.User,
        isArray: true,
    }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: 'Forbidden' }),
    (0, common_1.Get)(),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_d = typeof Request !== "undefined" && Request) === "function" ? _d : Object]),
    tslib_1.__metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], UsersController.prototype, "getUsers", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({ description: 'Success', type: models_1.User }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: 'Forbidden' }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'User not found' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'userId' }),
    (0, common_1.Get)(':userId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_f = typeof Request !== "undefined" && Request) === "function" ? _f : Object, typeof (_g = typeof get_user_params_1.GetUserParams !== "undefined" && get_user_params_1.GetUserParams) === "function" ? _g : Object]),
    tslib_1.__metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
], UsersController.prototype, "getUserById", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiCreatedResponse)({ description: 'Created' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiConflictResponse)({ description: 'User already exists' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Post)(),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_j = typeof Request !== "undefined" && Request) === "function" ? _j : Object, typeof (_k = typeof create_user_dto_1.CreateUserDto !== "undefined" && create_user_dto_1.CreateUserDto) === "function" ? _k : Object]),
    tslib_1.__metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], UsersController.prototype, "createUser", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'User not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'userId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Put)(':userId/status'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_m = typeof Request !== "undefined" && Request) === "function" ? _m : Object, typeof (_o = typeof get_user_params_1.GetUserParams !== "undefined" && get_user_params_1.GetUserParams) === "function" ? _o : Object, typeof (_p = typeof update_user_status_dto_1.UpdateUserStatusDto !== "undefined" && update_user_status_dto_1.UpdateUserStatusDto) === "function" ? _p : Object]),
    tslib_1.__metadata("design:returntype", typeof (_q = typeof Promise !== "undefined" && Promise) === "function" ? _q : Object)
], UsersController.prototype, "updateUserStatus", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'User not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'userId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Put)(':userId/password'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_r = typeof Request !== "undefined" && Request) === "function" ? _r : Object, typeof (_s = typeof get_user_params_1.GetUserParams !== "undefined" && get_user_params_1.GetUserParams) === "function" ? _s : Object, typeof (_t = typeof update_user_password_dto_1.UpdateUserPasswordDto !== "undefined" && update_user_password_dto_1.UpdateUserPasswordDto) === "function" ? _t : Object]),
    tslib_1.__metadata("design:returntype", typeof (_u = typeof Promise !== "undefined" && Promise) === "function" ? _u : Object)
], UsersController.prototype, "updateUserPassword", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'User not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'userId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Patch)(':userId/activities'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_v = typeof Request !== "undefined" && Request) === "function" ? _v : Object, typeof (_w = typeof get_user_params_1.GetUserParams !== "undefined" && get_user_params_1.GetUserParams) === "function" ? _w : Object, typeof (_x = typeof update_user_activities_dto_1.UpdateUserActivitiesDto !== "undefined" && update_user_activities_dto_1.UpdateUserActivitiesDto) === "function" ? _x : Object]),
    tslib_1.__metadata("design:returntype", typeof (_y = typeof Promise !== "undefined" && Promise) === "function" ? _y : Object)
], UsersController.prototype, "updateUserActivities", null);
UsersController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Users (Admin)'),
    (0, common_1.Controller)('users'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof users_assembler_1.UsersAssembler !== "undefined" && users_assembler_1.UsersAssembler) === "function" ? _b : Object, typeof (_c = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _c : Object])
], UsersController);
exports.UsersController = UsersController;


/***/ }),
/* 48 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const user_schema_1 = __webpack_require__(16);
const bcrypt = tslib_1.__importStar(__webpack_require__(15));
const assert_user_exists_1 = __webpack_require__(32);
const projects_service_1 = __webpack_require__(49);
const activities_service_1 = __webpack_require__(52);
const user_not_found_exception_1 = __webpack_require__(53);
let UsersService = class UsersService {
    constructor(userModel, projectsService, activitiesService) {
        this.userModel = userModel;
        this.projectsService = projectsService;
        this.activitiesService = activitiesService;
    }
    findAll() {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const findAll = this.userModel.find();
            return (_a = (yield this.populateAndExecuteQuery(findAll))) !== null && _a !== void 0 ? _a : [];
        });
    }
    findById(id) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const findById = this.userModel.findById(id);
            return (_a = (yield this.populateAndExecuteQuery(findById))) !== null && _a !== void 0 ? _a : undefined;
        });
    }
    findByEmail(email) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const findByEmail = this.findEnabledUserByEmail(email);
            return yield this.populateAndExecuteQuery(findByEmail);
        });
    }
    createUser(createUserDto) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const { firstName, lastName, email, password, role, status } = createUserDto;
            const existingUserRecord = yield this.findEnabledUserByEmail(email);
            if (existingUserRecord) {
                throw new common_1.ConflictException('User already exists');
            }
            const passwordHash = yield bcrypt.hash(password, 10);
            const userModel = new this.userModel({
                firstName,
                lastName,
                email,
                passwordHash,
                role,
                status,
                clients: [],
                projects: [],
                activities: [],
            });
            const userId = (_a = (yield userModel.save())) === null || _a === void 0 ? void 0 : _a.id;
            if (!userId) {
                throw new common_1.InternalServerErrorException('Failed to save user');
            }
            return userId;
        });
    }
    updateUserStatus(userId, status) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userRecord = yield this.userModel.findById(userId);
            if (!userRecord) {
                throw new user_not_found_exception_1.UserNotFoundException(userId);
            }
            yield userRecord.updateOne({
                status,
            });
        });
    }
    updateUserPassword(userId, password) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userRecord = yield this.userModel.findById(userId);
            if (!userRecord) {
                throw new user_not_found_exception_1.UserNotFoundException(userId);
            }
            const passwordHash = yield bcrypt.hash(password, 10);
            yield userRecord.updateOne({
                passwordHash,
            });
        });
    }
    updateUserActivities(userId, projectId, activityIds = []) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userRecord = yield this.findById(userId);
            if (!userRecord) {
                throw new user_not_found_exception_1.UserNotFoundException(userId);
            }
            const projectRecord = yield this.projectsService.findById(projectId);
            if (!projectRecord) {
                throw new common_1.BadRequestException(`project with id '${projectId}' not found`);
            }
            const uniqueActivityIds = [...new Set(activityIds)];
            yield this.validateActivitiesBelongToProject(projectId, uniqueActivityIds);
            if (!uniqueActivityIds.length) {
                yield this.removeAllUserActivitiesForProject(userRecord, projectRecord);
            }
            else {
                yield this.updateUserActivitiesForProject(userRecord, projectRecord, uniqueActivityIds);
            }
        });
    }
    changeUserPassword(userId, currentPassword, newPassword) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userRecord = yield this.userModel.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            const isCurrentPasswordCorrect = yield bcrypt.compare(currentPassword, userRecord.passwordHash);
            if (!isCurrentPasswordCorrect) {
                throw new common_1.BadRequestException('Invalid current password');
            }
            const hashedNewPassword = yield bcrypt.hash(newPassword, 10);
            userRecord.passwordHash = hashedNewPassword;
            yield userRecord.save();
        });
    }
    populateAndExecuteQuery(find) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            return ((_a = (yield find
                .populate('clients')
                .populate('projects')
                .populate('activities')
                .exec())) !== null && _a !== void 0 ? _a : undefined);
        });
    }
    findEnabledUserByEmail(email) {
        return this.userModel.findOne({
            email: email.toLowerCase(),
            status: 'enabled',
        });
    }
    validateActivitiesBelongToProject(projectId, activityIds) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const projectActivities = yield this.activitiesService.getActivities(undefined, undefined, projectId);
            const projectActivityIds = projectActivities.map((activity) => activity._id.toString());
            const invalidActivityIds = activityIds.filter((activityId) => !projectActivityIds.includes(activityId));
            if (invalidActivityIds.length > 0) {
                throw new common_1.BadRequestException(`one or more activities do not belong to project ${projectId}: ${invalidActivityIds.join(', ')}`);
            }
        });
    }
    removeAllUserActivitiesForProject(userRecord, projectRecord) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const projectId = projectRecord._id;
            const remainingActivities = userRecord.activities.filter((activity) => !activity.project._id.equals(projectId));
            const remainingProjects = userRecord.projects.filter((project) => !project._id.equals(projectId));
            const remainingClients = [];
            remainingProjects.forEach((project) => {
                const isClientInRemainingClients = remainingClients.find((clientRecord) => clientRecord._id.equals(project.client._id));
                if (!isClientInRemainingClients) {
                    remainingClients.push(project.client);
                }
            });
            yield this.userModel.updateOne({ _id: userRecord._id }, {
                clients: remainingClients,
                projects: remainingProjects,
                activities: remainingActivities,
            });
        });
    }
    updateUserActivitiesForProject(userRecord, projectRecord, uniqueActivityIds) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const updatedClients = [...userRecord.clients];
            const clientRecord = projectRecord.client;
            const foundClient = userRecord.clients.find((client) => client._id.equals(clientRecord._id));
            if (!foundClient) {
                updatedClients.push(clientRecord);
            }
            const updatedProjects = [...userRecord.projects];
            const foundProject = updatedProjects.find((project) => project._id.equals(projectRecord._id));
            if (!foundProject) {
                updatedProjects.push(projectRecord);
            }
            const updatedActivitiesIds = userRecord.activities
                .filter((activity) => !activity.project._id.equals(projectRecord._id))
                .map((activity) => activity._id.toString());
            const updatedActivityIdSet = new Set([...updatedActivitiesIds]);
            uniqueActivityIds.forEach((activityId) => {
                updatedActivityIdSet.add(activityId);
            });
            yield this.userModel.updateOne({ _id: userRecord._id }, {
                clients: updatedClients,
                projects: updatedProjects,
                activities: [...updatedActivityIdSet],
            });
        });
    }
};
UsersService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(user_schema_1.UserRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object, typeof (_b = typeof projects_service_1.ProjectsService !== "undefined" && projects_service_1.ProjectsService) === "function" ? _b : Object, typeof (_c = typeof activities_service_1.ActivitiesService !== "undefined" && activities_service_1.ActivitiesService) === "function" ? _c : Object])
], UsersService);
exports.UsersService = UsersService;


/***/ }),
/* 49 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProjectsService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const project_schema_1 = __webpack_require__(30);
const clients_service_1 = __webpack_require__(50);
const activity_schema_1 = __webpack_require__(28);
const timesheet_event_schema_1 = __webpack_require__(51);
const user_schema_1 = __webpack_require__(16);
let ProjectsService = class ProjectsService {
    constructor(projectModel, activityModel, timesheetEventModel, userModel, clientsService) {
        this.projectModel = projectModel;
        this.activityModel = activityModel;
        this.timesheetEventModel = timesheetEventModel;
        this.userModel = userModel;
        this.clientsService = clientsService;
    }
    findById(id) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const result = yield this.projectModel.findById(id).exec();
            return result !== null && result !== void 0 ? result : undefined;
        });
    }
    getProjectClientId(projectId) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!projectId) {
                return undefined;
            }
            const project = yield this.projectModel.findById(projectId).exec();
            return (_a = project === null || project === void 0 ? void 0 : project.client._id) !== null && _a !== void 0 ? _a : undefined;
        });
    }
    getProjects(status, clientId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!status && !clientId) {
                return yield this.projectModel.find().exec();
            }
            const filters = {};
            if (status) {
                filters.status = status;
            }
            if (clientId) {
                filters.client = clientId;
            }
            return yield this.projectModel.find(filters).exec();
        });
    }
    createProject(createProjectDto) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const { name, clientId, status } = createProjectDto;
            const clientRecord = yield this.clientsService.findById(clientId);
            if (!clientRecord) {
                throw new common_1.BadRequestException('Client does not exist');
            }
            const existingProjectRecord = yield this.findProjectByName(name, clientId);
            if (existingProjectRecord) {
                throw new common_1.ConflictException('Project with same name already exists for client');
            }
            const projectModel = new this.projectModel({
                name: name.trim(),
                client: clientId,
                status,
            });
            const projectId = (_a = (yield projectModel.save())) === null || _a === void 0 ? void 0 : _a.id;
            if (!projectId) {
                throw new common_1.InternalServerErrorException('Failed to save project');
            }
            return projectId;
        });
    }
    updateProject(projectId, updateProjectDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const { name, status } = updateProjectDto;
            const targetProject = yield this.findById(projectId);
            if (!targetProject) {
                throw new common_1.NotFoundException(`Project id not found`);
            }
            if (name) {
                const clientId = targetProject.client._id.toString();
                const duplicateProject = yield this.findProjectByName(name, clientId);
                if (duplicateProject && duplicateProject._id.toString() !== projectId) {
                    throw new common_1.ConflictException('Project with same name already exists for client');
                }
            }
            yield targetProject.updateOne({
                name: name === null || name === void 0 ? void 0 : name.trim(),
                status,
            });
        });
    }
    deleteProject(projectId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const targetProject = yield this.projectModel.findById(projectId);
            if (!targetProject) {
                throw new common_1.NotFoundException('Project id not found');
            }
            const assignedUser = yield this.userModel.findOne({
                projects: projectId,
            });
            if (assignedUser) {
                throw new common_1.BadRequestException('Cannot delete project assigned to user(s)');
            }
            const childActivities = yield this.activityModel.find({
                project: projectId,
            });
            for (const activity of childActivities) {
                const activityId = activity._id.toString();
                const timesheetEvent = yield this.timesheetEventModel.findOne({
                    activity: activityId,
                });
                if (timesheetEvent) {
                    throw new common_1.BadRequestException('Cannot delete project with any activity referenced in timesheet event(s)');
                }
            }
            yield this.activityModel.deleteMany({
                project: projectId,
            });
            yield targetProject.deleteOne();
        });
    }
    findProjectByName(name, clientId) {
        const projectNameRegex = '^' + name.trim() + '$';
        return this.projectModel.findOne({
            name: { $regex: projectNameRegex, $options: 'i' },
            client: clientId,
        });
    }
};
ProjectsService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(project_schema_1.ProjectRecord.name)),
    tslib_1.__param(1, (0, mongoose_1.InjectModel)(activity_schema_1.ActivityRecord.name)),
    tslib_1.__param(2, (0, mongoose_1.InjectModel)(timesheet_event_schema_1.TimesheetEventRecord.name)),
    tslib_1.__param(3, (0, mongoose_1.InjectModel)(user_schema_1.UserRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object, typeof (_b = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _b : Object, typeof (_c = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _c : Object, typeof (_d = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _d : Object, typeof (_e = typeof clients_service_1.ClientsService !== "undefined" && clients_service_1.ClientsService) === "function" ? _e : Object])
], ProjectsService);
exports.ProjectsService = ProjectsService;


/***/ }),
/* 50 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ClientsService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const client_schema_1 = __webpack_require__(29);
const activity_schema_1 = __webpack_require__(28);
const project_schema_1 = __webpack_require__(30);
const timesheet_event_schema_1 = __webpack_require__(51);
const user_schema_1 = __webpack_require__(16);
let ClientsService = class ClientsService {
    constructor(clientModel, activityModel, projectModel, timesheetEventModel, userModel) {
        this.clientModel = clientModel;
        this.activityModel = activityModel;
        this.projectModel = projectModel;
        this.timesheetEventModel = timesheetEventModel;
        this.userModel = userModel;
    }
    findById(id) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const result = yield this.clientModel.findById(id).exec();
            return result !== null && result !== void 0 ? result : undefined;
        });
    }
    getClients(status) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (status) {
                return yield this.clientModel.find({ status }).exec();
            }
            return yield this.clientModel.find().exec();
        });
    }
    createClient(createClientDto) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const { name, status, contactName, contactEmail, contactPhone, contactMethod, } = createClientDto;
            const existingClientRecord = yield this.findClientByName(name);
            if (existingClientRecord) {
                throw new common_1.ConflictException('Client with same name already exists');
            }
            const clientModel = new this.clientModel({
                name: name.trim(),
                status,
                contactName,
                contactEmail,
                contactPhone,
                contactMethod,
            });
            const clientId = (_a = (yield clientModel.save())) === null || _a === void 0 ? void 0 : _a.id;
            if (!clientId) {
                throw new common_1.InternalServerErrorException('Failed to save client');
            }
            return clientId;
        });
    }
    updateClient(clientId, updateClientDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const { name, status, contactName, contactEmail, contactPhone, contactMethod, } = updateClientDto;
            const targetClient = yield this.clientModel.findById(clientId);
            if (!targetClient) {
                throw new common_1.NotFoundException(`Client id not found`);
            }
            if (name) {
                const duplicateClient = yield this.findClientByName(name);
                if (duplicateClient && duplicateClient._id.toString() !== clientId) {
                    throw new common_1.ConflictException('Client with same name already exists');
                }
            }
            const setFields = {};
            const unsetFields = {};
            if (name) {
                setFields.name = name.trim();
            }
            if (status) {
                setFields.status = status;
            }
            if (contactMethod) {
                setFields.contactMethod = contactMethod;
            }
            if (contactName) {
                setFields.contactName = contactName;
            }
            else if (contactName === null) {
                unsetFields.contactName = '';
            }
            if (contactEmail) {
                setFields.contactEmail = contactEmail;
            }
            else if (contactEmail === null) {
                unsetFields.contactEmail = '';
            }
            if (contactPhone) {
                setFields.contactPhone = contactPhone;
            }
            else if (contactPhone === null) {
                unsetFields.contactPhone = '';
            }
            yield targetClient.updateOne({
                $set: setFields,
                $unset: unsetFields,
            });
        });
    }
    deleteClient(clientId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const targetClient = yield this.clientModel.findById(clientId);
            if (!targetClient) {
                throw new common_1.NotFoundException('Client id not found');
            }
            const assignedUser = yield this.userModel.findOne({
                clients: clientId,
            });
            if (assignedUser) {
                throw new common_1.BadRequestException('Cannot delete client assigned to user(s)');
            }
            const childActivities = yield this.activityModel.find({
                client: clientId,
            });
            for (const activity of childActivities) {
                const activityId = activity._id.toString();
                const timesheetEvent = yield this.timesheetEventModel.findOne({
                    activity: activityId,
                });
                if (timesheetEvent) {
                    throw new common_1.BadRequestException('Cannot delete client with any activity referenced in timesheet event(s)');
                }
            }
            yield this.activityModel.deleteMany({
                client: clientId,
            });
            yield this.projectModel.deleteMany({
                client: clientId,
            });
            yield targetClient.deleteOne();
        });
    }
    findClientByName(name) {
        const clientNameRegex = '^' + name.trim() + '$';
        return this.clientModel.findOne({
            name: { $regex: clientNameRegex, $options: 'i' },
        });
    }
};
ClientsService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(client_schema_1.ClientRecord.name)),
    tslib_1.__param(1, (0, mongoose_1.InjectModel)(activity_schema_1.ActivityRecord.name)),
    tslib_1.__param(2, (0, mongoose_1.InjectModel)(project_schema_1.ProjectRecord.name)),
    tslib_1.__param(3, (0, mongoose_1.InjectModel)(timesheet_event_schema_1.TimesheetEventRecord.name)),
    tslib_1.__param(4, (0, mongoose_1.InjectModel)(user_schema_1.UserRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object, typeof (_b = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _b : Object, typeof (_c = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _c : Object, typeof (_d = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _d : Object, typeof (_e = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _e : Object])
], ClientsService);
exports.ClientsService = ClientsService;


/***/ }),
/* 51 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TimesheetEventSchema = exports.TimesheetEventRecord = void 0;
const tslib_1 = __webpack_require__(2);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const user_schema_1 = __webpack_require__(16);
const activity_schema_1 = __webpack_require__(28);
const models_1 = __webpack_require__(17);
const project_schema_1 = __webpack_require__(30);
const client_schema_1 = __webpack_require__(29);
let TimesheetEventRecord = class TimesheetEventRecord {
};
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.SchemaTypes.ObjectId, ref: user_schema_1.UserRecord.name, required: true }),
    tslib_1.__metadata("design:type", typeof (_a = typeof user_schema_1.UserRecord !== "undefined" && user_schema_1.UserRecord) === "function" ? _a : Object)
], TimesheetEventRecord.prototype, "user", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], TimesheetEventRecord.prototype, "date", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", Number)
], TimesheetEventRecord.prototype, "durationMinutes", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true, default: 'work', type: String }),
    tslib_1.__metadata("design:type", typeof (_b = typeof models_1.TimesheetEventType !== "undefined" && models_1.TimesheetEventType) === "function" ? _b : Object)
], TimesheetEventRecord.prototype, "eventType", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: false }),
    tslib_1.__metadata("design:type", String)
], TimesheetEventRecord.prototype, "comment", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({
        type: mongoose_2.SchemaTypes.ObjectId,
        ref: activity_schema_1.ActivityRecord.name,
        required: false,
    }),
    tslib_1.__metadata("design:type", typeof (_c = typeof activity_schema_1.ActivityRecord !== "undefined" && activity_schema_1.ActivityRecord) === "function" ? _c : Object)
], TimesheetEventRecord.prototype, "activity", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({
        type: mongoose_2.SchemaTypes.ObjectId,
        ref: project_schema_1.ProjectRecord.name,
        required: false,
    }),
    tslib_1.__metadata("design:type", typeof (_d = typeof project_schema_1.ProjectRecord !== "undefined" && project_schema_1.ProjectRecord) === "function" ? _d : Object)
], TimesheetEventRecord.prototype, "project", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({
        type: mongoose_2.SchemaTypes.ObjectId,
        ref: client_schema_1.ClientRecord.name,
        required: false,
    }),
    tslib_1.__metadata("design:type", typeof (_e = typeof client_schema_1.ClientRecord !== "undefined" && client_schema_1.ClientRecord) === "function" ? _e : Object)
], TimesheetEventRecord.prototype, "client", void 0);
TimesheetEventRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'timesheetEvents' })
], TimesheetEventRecord);
exports.TimesheetEventRecord = TimesheetEventRecord;
const TimesheetEventSchema = mongoose_1.SchemaFactory.createForClass(TimesheetEventRecord);
exports.TimesheetEventSchema = TimesheetEventSchema;


/***/ }),
/* 52 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ActivitiesService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const activity_schema_1 = __webpack_require__(28);
const timesheet_event_schema_1 = __webpack_require__(51);
const user_schema_1 = __webpack_require__(16);
const projects_service_1 = __webpack_require__(49);
let ActivitiesService = class ActivitiesService {
    constructor(activityModel, timesheetEventModel, userModel, projectsService) {
        this.activityModel = activityModel;
        this.timesheetEventModel = timesheetEventModel;
        this.userModel = userModel;
        this.projectsService = projectsService;
    }
    findById(id) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const result = yield this.activityModel.findById(id).exec();
            return result !== null && result !== void 0 ? result : undefined;
        });
    }
    getActivityProjectId(activityId) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!activityId) {
                return undefined;
            }
            const activity = yield this.activityModel.findById(activityId).exec();
            return (_a = activity === null || activity === void 0 ? void 0 : activity.project._id) !== null && _a !== void 0 ? _a : undefined;
        });
    }
    getActivities(status, clientId, projectId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!status && !clientId && !projectId) {
                return yield this.activityModel.find().exec();
            }
            const filters = {};
            if (status) {
                filters.status = status;
            }
            if (clientId) {
                filters.client = clientId;
            }
            if (projectId) {
                filters.project = projectId;
            }
            return yield this.activityModel.find(filters).exec();
        });
    }
    createActivity(createActivityDto) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const { name, projectId, status } = createActivityDto;
            const projectRecord = yield this.projectsService.findById(projectId);
            if (!projectRecord) {
                throw new common_1.BadRequestException('Project does not exist');
            }
            const existingActivityRecord = yield this.findActivityByName(name, projectId);
            if (existingActivityRecord) {
                throw new common_1.ConflictException('Activity with same name already exists for project');
            }
            const clientId = yield this.projectsService.getProjectClientId(projectId);
            const activityModel = new this.activityModel({
                name: name.trim(),
                client: clientId,
                project: projectId,
                status,
            });
            const activityId = (_a = (yield activityModel.save())) === null || _a === void 0 ? void 0 : _a.id;
            if (!activityId) {
                throw new common_1.InternalServerErrorException('Failed to save activity');
            }
            return activityId;
        });
    }
    updateActivity(activityId, updateActivityDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const { name, status } = updateActivityDto;
            const targetActivity = yield this.findById(activityId);
            if (!targetActivity) {
                throw new common_1.NotFoundException(`Activity id not found`);
            }
            if (name) {
                const projectId = targetActivity.project._id.toString();
                const duplicateActivity = yield this.findActivityByName(name, projectId);
                if (duplicateActivity &&
                    duplicateActivity._id.toString() !== activityId) {
                    throw new common_1.ConflictException('Activity with same name already exists for project');
                }
            }
            yield targetActivity.updateOne({
                name: name === null || name === void 0 ? void 0 : name.trim(),
                status,
            });
        });
    }
    deleteActivity(activityId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const targetActivity = yield this.activityModel.findById(activityId);
            if (!targetActivity) {
                throw new common_1.NotFoundException('Activity id not found');
            }
            const assignedUser = yield this.userModel.findOne({
                activities: activityId,
            });
            if (assignedUser) {
                throw new common_1.BadRequestException('Cannot delete activity assigned to user(s)');
            }
            const timesheetEvent = yield this.timesheetEventModel.findOne({
                activity: activityId,
            });
            if (timesheetEvent) {
                throw new common_1.BadRequestException('Cannot delete activity referenced in timesheet event(s)');
            }
            yield targetActivity.deleteOne();
        });
    }
    findActivityByName(name, projectId) {
        const activityNameRegex = '^' + name.trim() + '$';
        return this.activityModel.findOne({
            name: { $regex: activityNameRegex, $options: 'i' },
            project: projectId,
        });
    }
};
ActivitiesService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(activity_schema_1.ActivityRecord.name)),
    tslib_1.__param(1, (0, mongoose_1.InjectModel)(timesheet_event_schema_1.TimesheetEventRecord.name)),
    tslib_1.__param(2, (0, mongoose_1.InjectModel)(user_schema_1.UserRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object, typeof (_b = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _b : Object, typeof (_c = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _c : Object, typeof (_d = typeof projects_service_1.ProjectsService !== "undefined" && projects_service_1.ProjectsService) === "function" ? _d : Object])
], ActivitiesService);
exports.ActivitiesService = ActivitiesService;


/***/ }),
/* 53 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserNotFoundException = void 0;
const common_1 = __webpack_require__(7);
class UserNotFoundException extends common_1.NotFoundException {
    constructor(userId) {
        super(`no user found for id '${userId}'`);
    }
}
exports.UserNotFoundException = UserNotFoundException;


/***/ }),
/* 54 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersAssembler = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
let UsersAssembler = class UsersAssembler {
    constructor(configService) {
        this.configService = configService;
    }
    assembleUser(userRecord) {
        return {
            id: userRecord._id.toString(),
            firstName: userRecord.firstName,
            lastName: userRecord.lastName,
            email: userRecord.email,
            role: userRecord.role,
            status: userRecord.status,
            organization: this.configService.get('organization', { infer: true }),
            clients: this.assembleAssignedClients(userRecord.clients),
            projects: this.assembleAssignedProjects(userRecord.projects),
            activities: this.assembleAssignedActivities(userRecord.activities),
        };
    }
    assembleAssignedClients(assignedClientRecords = []) {
        return assignedClientRecords.map((clientRecord) => ({
            id: clientRecord._id.toString(),
            name: clientRecord.name,
        }));
    }
    assembleAssignedProjects(assignedProjectRecords = []) {
        return assignedProjectRecords.map((projectRecord) => ({
            id: projectRecord._id.toString(),
            name: projectRecord.name,
        }));
    }
    assembleAssignedActivities(assignedActivityRecords = []) {
        return assignedActivityRecords.map((activityRecord) => ({
            id: activityRecord._id.toString(),
            name: activityRecord.name,
        }));
    }
};
UsersAssembler = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], UsersAssembler);
exports.UsersAssembler = UsersAssembler;


/***/ }),
/* 55 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetUserParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class GetUserParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], GetUserParams.prototype, "userId", void 0);
exports.GetUserParams = GetUserParams;


/***/ }),
/* 56 */
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),
/* 57 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateUserDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const models_1 = __webpack_require__(17);
const is_not_blank_string_validator_1 = __webpack_require__(58);
class CreateUserDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Jane' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateUserDto.prototype, "firstName", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Doe' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateUserDto.prototype, "lastName", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'jane.doe@somewhere.com' }),
    (0, class_validator_1.IsEmail)({ allow_utf8_local_part: false }, { message: 'email must be a valid email address' }),
    tslib_1.__metadata("design:type", String)
], CreateUserDto.prototype, "email", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'password' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateUserDto.prototype, "password", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.userRoleList,
        example: 'member',
    }),
    (0, class_validator_1.IsIn)(models_1.userRoleList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.UserRole !== "undefined" && models_1.UserRole) === "function" ? _a : Object)
], CreateUserDto.prototype, "role", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.userStatusList,
        example: 'enabled',
    }),
    (0, class_validator_1.IsIn)(models_1.userStatusList),
    tslib_1.__metadata("design:type", typeof (_b = typeof models_1.UserStatus !== "undefined" && models_1.UserStatus) === "function" ? _b : Object)
], CreateUserDto.prototype, "status", void 0);
exports.CreateUserDto = CreateUserDto;


/***/ }),
/* 58 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IsNotBlankString = exports.IsNotBlankStringValidator = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
let IsNotBlankStringValidator = class IsNotBlankStringValidator {
    validate(value) {
        return !!(value === null || value === void 0 ? void 0 : value.trim());
    }
    defaultMessage({ property }) {
        return `${property} must not be an empty string or only white spaces`;
    }
};
IsNotBlankStringValidator = tslib_1.__decorate([
    (0, class_validator_1.ValidatorConstraint)({ name: 'isNotBlankString', async: false })
], IsNotBlankStringValidator);
exports.IsNotBlankStringValidator = IsNotBlankStringValidator;
function IsNotBlankString(validationOptions) {
    return function (object, propertyName) {
        (0, class_validator_1.registerDecorator)({
            target: object.constructor,
            propertyName,
            options: validationOptions,
            constraints: [],
            validator: IsNotBlankStringValidator,
        });
    };
}
exports.IsNotBlankString = IsNotBlankString;


/***/ }),
/* 59 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateUserStatusDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const models_1 = __webpack_require__(17);
class UpdateUserStatusDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.userStatusList,
        example: 'enabled',
    }),
    (0, class_validator_1.IsIn)(models_1.userStatusList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.UserStatus !== "undefined" && models_1.UserStatus) === "function" ? _a : Object)
], UpdateUserStatusDto.prototype, "status", void 0);
exports.UpdateUserStatusDto = UpdateUserStatusDto;


/***/ }),
/* 60 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateUserPasswordDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const is_not_blank_string_validator_1 = __webpack_require__(58);
class UpdateUserPasswordDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], UpdateUserPasswordDto.prototype, "password", void 0);
exports.UpdateUserPasswordDto = UpdateUserPasswordDto;


/***/ }),
/* 61 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateUserActivitiesDto = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
const swagger_1 = __webpack_require__(5);
class UpdateUserActivitiesDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], UpdateUserActivitiesDto.prototype, "projectId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: false, isArray: true, example: [] }),
    (0, class_validator_1.IsMongoId)({ each: true }),
    tslib_1.__metadata("design:type", Array)
], UpdateUserActivitiesDto.prototype, "activityIds", void 0);
exports.UpdateUserActivitiesDto = UpdateUserActivitiesDto;


/***/ }),
/* 62 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserRecordHelper = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
let UserRecordHelper = class UserRecordHelper {
    getAssignedActivity(userRecord, activityId) {
        var _a;
        const assignedActivities = userRecord.activities;
        return ((_a = assignedActivities.find((activity) => {
            return activity._id.equals(activityId);
        })) !== null && _a !== void 0 ? _a : undefined);
    }
    getAssignedProject(userRecord, projectId) {
        var _a;
        const assignedProjects = userRecord.projects;
        return ((_a = assignedProjects.find((project) => {
            return project._id.equals(projectId);
        })) !== null && _a !== void 0 ? _a : undefined);
    }
};
UserRecordHelper = tslib_1.__decorate([
    (0, common_1.Injectable)()
], UserRecordHelper);
exports.UserRecordHelper = UserRecordHelper;


/***/ }),
/* 63 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProjectsModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const projects_controller_1 = __webpack_require__(64);
const projects_service_1 = __webpack_require__(49);
const project_schema_1 = __webpack_require__(30);
const auth_module_1 = __webpack_require__(10);
const clients_module_1 = __webpack_require__(71);
const activity_schema_1 = __webpack_require__(28);
const timesheet_event_schema_1 = __webpack_require__(51);
const user_schema_1 = __webpack_require__(16);
let ProjectsModule = class ProjectsModule {
};
ProjectsModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [projects_controller_1.ProjectsController],
        providers: [projects_service_1.ProjectsService],
        imports: [
            mongoose_1.MongooseModule.forFeature([
                {
                    name: project_schema_1.ProjectRecord.name,
                    schema: project_schema_1.ProjectSchema,
                },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: activity_schema_1.ActivityRecord.name,
                    schema: activity_schema_1.ActivitySchema,
                },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: timesheet_event_schema_1.TimesheetEventRecord.name,
                    schema: timesheet_event_schema_1.TimesheetEventSchema,
                },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: user_schema_1.UserRecord.name,
                    schema: user_schema_1.UserSchema,
                },
            ]),
            auth_module_1.AuthModule,
            clients_module_1.ClientsModule,
        ],
        exports: [projects_service_1.ProjectsService],
    })
], ProjectsModule);
exports.ProjectsModule = ProjectsModule;


/***/ }),
/* 64 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProjectsController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const swagger_1 = __webpack_require__(5);
const projects_service_1 = __webpack_require__(49);
const project_1 = __webpack_require__(65);
const get_projects_query_params_1 = __webpack_require__(66);
const create_project_dto_1 = __webpack_require__(67);
const update_project_params_1 = __webpack_require__(68);
const update_project_dto_1 = __webpack_require__(69);
const auth_service_1 = __webpack_require__(13);
const delete_project_params_1 = __webpack_require__(70);
let ProjectsController = class ProjectsController {
    constructor(projectsService, authService) {
        this.projectsService = projectsService;
        this.authService = authService;
    }
    getProjects({ status, clientId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const projectRecords = yield this.projectsService.getProjects(status, clientId);
            const result = projectRecords.map((item) => ({
                id: item._id.toString(),
                name: item.name,
                status: item.status,
                clientId: item.client._id.toString(),
            }));
            return result;
        });
    }
    createProject(request, createProjectDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            const id = yield this.projectsService.createProject(createProjectDto);
            return { id };
        });
    }
    updateProject(request, { projectId }, updateProjectDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.projectsService.updateProject(projectId, updateProjectDto);
        });
    }
    deleteProject(request, { projectId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.projectsService.deleteProject(projectId);
        });
    }
};
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({
        description: 'Success',
        type: project_1.Project,
        isArray: true,
    }),
    (0, swagger_1.ApiBadRequestResponse)({
        description: 'Invalid status \t\n Invalid client id format (not a MongoDb ObjectId)',
    }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Get)(),
    tslib_1.__param(0, (0, common_1.Query)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_c = typeof get_projects_query_params_1.GetProjectsQueryParams !== "undefined" && get_projects_query_params_1.GetProjectsQueryParams) === "function" ? _c : Object]),
    tslib_1.__metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], ProjectsController.prototype, "getProjects", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiCreatedResponse)({ description: 'Created' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiConflictResponse)({
        description: 'Project with same name already exists for client',
    }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Post)(),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_e = typeof Request !== "undefined" && Request) === "function" ? _e : Object, typeof (_f = typeof create_project_dto_1.CreateProjectDto !== "undefined" && create_project_dto_1.CreateProjectDto) === "function" ? _f : Object]),
    tslib_1.__metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], ProjectsController.prototype, "createProject", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Project id not found' }),
    (0, swagger_1.ApiConflictResponse)({
        description: 'Project with same name already exists for client',
    }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'projectId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Patch)(':projectId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_h = typeof Request !== "undefined" && Request) === "function" ? _h : Object, typeof (_j = typeof update_project_params_1.UpdateProjectParams !== "undefined" && update_project_params_1.UpdateProjectParams) === "function" ? _j : Object, typeof (_k = typeof update_project_dto_1.UpdateProjectDto !== "undefined" && update_project_dto_1.UpdateProjectDto) === "function" ? _k : Object]),
    tslib_1.__metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], ProjectsController.prototype, "updateProject", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Project id not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'projectId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Delete)(':projectId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_m = typeof Request !== "undefined" && Request) === "function" ? _m : Object, typeof (_o = typeof delete_project_params_1.DeleteProjectParams !== "undefined" && delete_project_params_1.DeleteProjectParams) === "function" ? _o : Object]),
    tslib_1.__metadata("design:returntype", typeof (_p = typeof Promise !== "undefined" && Promise) === "function" ? _p : Object)
], ProjectsController.prototype, "deleteProject", null);
ProjectsController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Projects'),
    (0, common_1.Controller)('projects'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof projects_service_1.ProjectsService !== "undefined" && projects_service_1.ProjectsService) === "function" ? _a : Object, typeof (_b = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _b : Object])
], ProjectsController);
exports.ProjectsController = ProjectsController;


/***/ }),
/* 65 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Project = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
class Project {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", String)
], Project.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", String)
], Project.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ProjectStatus !== "undefined" && models_1.ProjectStatus) === "function" ? _a : Object)
], Project.prototype, "status", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", String)
], Project.prototype, "clientId", void 0);
exports.Project = Project;


/***/ }),
/* 66 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetProjectsQueryParams = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
const class_validator_1 = __webpack_require__(56);
class GetProjectsQueryParams {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        example: 'active',
        enum: models_1.projectStatusList,
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsIn)(models_1.projectStatusList),
    tslib_1.__metadata("design:type", Object)
], GetProjectsQueryParams.prototype, "status", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        type: String,
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", Object)
], GetProjectsQueryParams.prototype, "clientId", void 0);
exports.GetProjectsQueryParams = GetProjectsQueryParams;


/***/ }),
/* 67 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateProjectDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const models_1 = __webpack_require__(17);
const is_not_blank_string_validator_1 = __webpack_require__(58);
class CreateProjectDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Time Tracker' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateProjectDto.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], CreateProjectDto.prototype, "clientId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.projectStatusList,
        example: 'active',
    }),
    (0, class_validator_1.IsIn)(models_1.projectStatusList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ProjectStatus !== "undefined" && models_1.ProjectStatus) === "function" ? _a : Object)
], CreateProjectDto.prototype, "status", void 0);
exports.CreateProjectDto = CreateProjectDto;


/***/ }),
/* 68 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateProjectParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class UpdateProjectParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], UpdateProjectParams.prototype, "projectId", void 0);
exports.UpdateProjectParams = UpdateProjectParams;


/***/ }),
/* 69 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateProjectDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const is_not_blank_string_validator_1 = __webpack_require__(58);
const models_1 = __webpack_require__(17);
class UpdateProjectDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Time Tracker' }),
    (0, class_validator_1.IsOptional)(),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], UpdateProjectDto.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.projectStatusList,
        example: 'active',
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsIn)(models_1.projectStatusList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ProjectStatus !== "undefined" && models_1.ProjectStatus) === "function" ? _a : Object)
], UpdateProjectDto.prototype, "status", void 0);
exports.UpdateProjectDto = UpdateProjectDto;


/***/ }),
/* 70 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DeleteProjectParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class DeleteProjectParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], DeleteProjectParams.prototype, "projectId", void 0);
exports.DeleteProjectParams = DeleteProjectParams;


/***/ }),
/* 71 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ClientsModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const clients_controller_1 = __webpack_require__(72);
const clients_service_1 = __webpack_require__(50);
const client_schema_1 = __webpack_require__(29);
const activity_schema_1 = __webpack_require__(28);
const project_schema_1 = __webpack_require__(30);
const timesheet_event_schema_1 = __webpack_require__(51);
const user_schema_1 = __webpack_require__(16);
const auth_module_1 = __webpack_require__(10);
let ClientsModule = class ClientsModule {
};
ClientsModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [clients_controller_1.ClientsController],
        providers: [clients_service_1.ClientsService],
        imports: [
            mongoose_1.MongooseModule.forFeature([
                { name: client_schema_1.ClientRecord.name, schema: client_schema_1.ClientSchema },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: activity_schema_1.ActivityRecord.name,
                    schema: activity_schema_1.ActivitySchema,
                },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: project_schema_1.ProjectRecord.name,
                    schema: project_schema_1.ProjectSchema,
                },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: timesheet_event_schema_1.TimesheetEventRecord.name,
                    schema: timesheet_event_schema_1.TimesheetEventSchema,
                },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: user_schema_1.UserRecord.name,
                    schema: user_schema_1.UserSchema,
                },
            ]),
            auth_module_1.AuthModule,
        ],
        exports: [clients_service_1.ClientsService],
    })
], ClientsModule);
exports.ClientsModule = ClientsModule;


/***/ }),
/* 72 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ClientsController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const swagger_1 = __webpack_require__(5);
const clients_service_1 = __webpack_require__(50);
const auth_service_1 = __webpack_require__(13);
const create_client_dto_1 = __webpack_require__(73);
const client_1 = __webpack_require__(74);
const get_clients_query_params_1 = __webpack_require__(75);
const update_client_params_1 = __webpack_require__(76);
const update_client_dto_1 = __webpack_require__(77);
const delete_client_params_1 = __webpack_require__(78);
let ClientsController = class ClientsController {
    constructor(clientsService, authService) {
        this.clientsService = clientsService;
        this.authService = authService;
    }
    getClients({ status }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const clientRecords = yield this.clientsService.getClients(status);
            const result = clientRecords.map((item) => ({
                id: item._id.toString(),
                name: item.name,
                status: item.status,
                contactName: item.contactName,
                contactEmail: item.contactEmail,
                contactPhone: item.contactPhone,
                contactMethod: item.contactMethod,
            }));
            return result;
        });
    }
    createClient(request, createClientDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            const id = yield this.clientsService.createClient(createClientDto);
            return { id };
        });
    }
    updateClient(request, { clientId }, updateClientDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.clientsService.updateClient(clientId, updateClientDto);
        });
    }
    deleteClient(request, { clientId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.clientsService.deleteClient(clientId);
        });
    }
};
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({
        description: 'Success',
        type: client_1.Client,
        isArray: true,
    }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Invalid status' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Get)(),
    tslib_1.__param(0, (0, common_1.Query)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_c = typeof get_clients_query_params_1.GetClientsQueryParams !== "undefined" && get_clients_query_params_1.GetClientsQueryParams) === "function" ? _c : Object]),
    tslib_1.__metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], ClientsController.prototype, "getClients", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiCreatedResponse)({ description: 'Created' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiConflictResponse)({ description: 'Client with same name already exists' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Post)(),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_e = typeof Request !== "undefined" && Request) === "function" ? _e : Object, typeof (_f = typeof create_client_dto_1.CreateClientDto !== "undefined" && create_client_dto_1.CreateClientDto) === "function" ? _f : Object]),
    tslib_1.__metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], ClientsController.prototype, "createClient", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Client id not found' }),
    (0, swagger_1.ApiConflictResponse)({ description: 'Client with same name already exists' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'clientId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Patch)(':clientId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_h = typeof Request !== "undefined" && Request) === "function" ? _h : Object, typeof (_j = typeof update_client_params_1.UpdateClientParams !== "undefined" && update_client_params_1.UpdateClientParams) === "function" ? _j : Object, typeof (_k = typeof update_client_dto_1.UpdateClientDto !== "undefined" && update_client_dto_1.UpdateClientDto) === "function" ? _k : Object]),
    tslib_1.__metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], ClientsController.prototype, "updateClient", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Client id not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'clientId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Delete)(':clientId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_m = typeof Request !== "undefined" && Request) === "function" ? _m : Object, typeof (_o = typeof delete_client_params_1.DeleteClientParams !== "undefined" && delete_client_params_1.DeleteClientParams) === "function" ? _o : Object]),
    tslib_1.__metadata("design:returntype", typeof (_p = typeof Promise !== "undefined" && Promise) === "function" ? _p : Object)
], ClientsController.prototype, "deleteClient", null);
ClientsController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Clients'),
    (0, common_1.Controller)('clients'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof clients_service_1.ClientsService !== "undefined" && clients_service_1.ClientsService) === "function" ? _a : Object, typeof (_b = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _b : Object])
], ClientsController);
exports.ClientsController = ClientsController;


/***/ }),
/* 73 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateClientDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const models_1 = __webpack_require__(17);
const is_not_blank_string_validator_1 = __webpack_require__(58);
class CreateClientDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Microsoft' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateClientDto.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.clientStatusList,
        example: 'active',
    }),
    (0, class_validator_1.IsIn)(models_1.clientStatusList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ClientStatus !== "undefined" && models_1.ClientStatus) === "function" ? _a : Object)
], CreateClientDto.prototype, "status", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'John Smith' }),
    (0, class_validator_1.IsOptional)(),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateClientDto.prototype, "contactName", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'john.smith@client.com' }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEmail)(),
    tslib_1.__metadata("design:type", String)
], CreateClientDto.prototype, "contactEmail", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: '16042223333' }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumberString)(),
    tslib_1.__metadata("design:type", String)
], CreateClientDto.prototype, "contactPhone", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.clientContactMethodList,
        example: 'email',
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsIn)(models_1.clientContactMethodList),
    tslib_1.__metadata("design:type", typeof (_b = typeof models_1.ClientContactMethod !== "undefined" && models_1.ClientContactMethod) === "function" ? _b : Object)
], CreateClientDto.prototype, "contactMethod", void 0);
exports.CreateClientDto = CreateClientDto;


/***/ }),
/* 74 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Client = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
class Client {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", String)
], Client.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", String)
], Client.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ClientStatus !== "undefined" && models_1.ClientStatus) === "function" ? _a : Object)
], Client.prototype, "status", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    tslib_1.__metadata("design:type", String)
], Client.prototype, "contactName", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    tslib_1.__metadata("design:type", String)
], Client.prototype, "contactEmail", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    tslib_1.__metadata("design:type", String)
], Client.prototype, "contactPhone", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    tslib_1.__metadata("design:type", typeof (_b = typeof models_1.ClientContactMethod !== "undefined" && models_1.ClientContactMethod) === "function" ? _b : Object)
], Client.prototype, "contactMethod", void 0);
exports.Client = Client;


/***/ }),
/* 75 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetClientsQueryParams = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
const class_validator_1 = __webpack_require__(56);
class GetClientsQueryParams {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        example: 'active',
        enum: models_1.clientStatusList,
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsIn)(models_1.clientStatusList),
    tslib_1.__metadata("design:type", Object)
], GetClientsQueryParams.prototype, "status", void 0);
exports.GetClientsQueryParams = GetClientsQueryParams;


/***/ }),
/* 76 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateClientParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class UpdateClientParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], UpdateClientParams.prototype, "clientId", void 0);
exports.UpdateClientParams = UpdateClientParams;


/***/ }),
/* 77 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateClientDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const is_not_blank_string_validator_1 = __webpack_require__(58);
const models_1 = __webpack_require__(17);
class UpdateClientDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Microsoft' }),
    (0, class_validator_1.IsOptional)(),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], UpdateClientDto.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.clientStatusList,
        example: 'active',
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsIn)(models_1.clientStatusList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ClientStatus !== "undefined" && models_1.ClientStatus) === "function" ? _a : Object)
], UpdateClientDto.prototype, "status", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'John Smith' }),
    (0, class_validator_1.IsOptional)(),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", Object)
], UpdateClientDto.prototype, "contactName", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'john.smith@client.com' }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEmail)(),
    tslib_1.__metadata("design:type", Object)
], UpdateClientDto.prototype, "contactEmail", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: '16042223333' }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumberString)(),
    tslib_1.__metadata("design:type", Object)
], UpdateClientDto.prototype, "contactPhone", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.clientContactMethodList,
        example: 'email',
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsIn)(models_1.clientContactMethodList),
    tslib_1.__metadata("design:type", typeof (_b = typeof models_1.ClientContactMethod !== "undefined" && models_1.ClientContactMethod) === "function" ? _b : Object)
], UpdateClientDto.prototype, "contactMethod", void 0);
exports.UpdateClientDto = UpdateClientDto;


/***/ }),
/* 78 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DeleteClientParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class DeleteClientParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], DeleteClientParams.prototype, "clientId", void 0);
exports.DeleteClientParams = DeleteClientParams;


/***/ }),
/* 79 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ActivitiesModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const activities_controller_1 = __webpack_require__(80);
const activities_service_1 = __webpack_require__(52);
const activity_schema_1 = __webpack_require__(28);
const timesheet_event_schema_1 = __webpack_require__(51);
const user_schema_1 = __webpack_require__(16);
const auth_module_1 = __webpack_require__(10);
const projects_module_1 = __webpack_require__(63);
let ActivitiesModule = class ActivitiesModule {
};
ActivitiesModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [activities_controller_1.ActivitiesController],
        providers: [activities_service_1.ActivitiesService],
        imports: [
            mongoose_1.MongooseModule.forFeature([
                {
                    name: activity_schema_1.ActivityRecord.name,
                    schema: activity_schema_1.ActivitySchema,
                },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: timesheet_event_schema_1.TimesheetEventRecord.name,
                    schema: timesheet_event_schema_1.TimesheetEventSchema,
                },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: user_schema_1.UserRecord.name,
                    schema: user_schema_1.UserSchema,
                },
            ]),
            auth_module_1.AuthModule,
            projects_module_1.ProjectsModule,
        ],
        exports: [activities_service_1.ActivitiesService],
    })
], ActivitiesModule);
exports.ActivitiesModule = ActivitiesModule;


/***/ }),
/* 80 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ActivitiesController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const swagger_1 = __webpack_require__(5);
const activities_service_1 = __webpack_require__(52);
const activity_1 = __webpack_require__(81);
const get_activities_query_params_1 = __webpack_require__(82);
const create_activity_dto_1 = __webpack_require__(83);
const update_activity_params_1 = __webpack_require__(84);
const update_activity_dto_1 = __webpack_require__(85);
const delete_activity_params_1 = __webpack_require__(86);
const auth_service_1 = __webpack_require__(13);
let ActivitiesController = class ActivitiesController {
    constructor(activitiesService, authService) {
        this.activitiesService = activitiesService;
        this.authService = authService;
    }
    getActivities({ status, clientId, projectId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const activityRecords = yield this.activitiesService.getActivities(status, clientId, projectId);
            const result = activityRecords.map((item) => ({
                id: item._id.toString(),
                name: item.name,
                status: item.status,
                clientId: item.client._id.toString(),
                projectId: item.project._id.toString(),
            }));
            return result;
        });
    }
    createActivity(request, createActivityDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            const id = yield this.activitiesService.createActivity(createActivityDto);
            return { id };
        });
    }
    updateActivity(request, { activityId }, updateActivityDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.activitiesService.updateActivity(activityId, updateActivityDto);
        });
    }
    deleteActivity(request, { activityId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.activitiesService.deleteActivity(activityId);
        });
    }
};
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({
        description: 'Success',
        type: activity_1.Activity,
        isArray: true,
    }),
    (0, swagger_1.ApiBadRequestResponse)({
        description: 'Invalid status \t\n Invalid client id format (not a MongoDb ObjectId) \t\n Invalid project id format (not a MongoDB ObjectId)',
    }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Get)(),
    tslib_1.__param(0, (0, common_1.Query)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_c = typeof get_activities_query_params_1.GetActivitiesQueryParams !== "undefined" && get_activities_query_params_1.GetActivitiesQueryParams) === "function" ? _c : Object]),
    tslib_1.__metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], ActivitiesController.prototype, "getActivities", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiCreatedResponse)({ description: 'Created' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiConflictResponse)({
        description: 'Activity with same name already exists for project',
    }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Post)(),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_e = typeof Request !== "undefined" && Request) === "function" ? _e : Object, typeof (_f = typeof create_activity_dto_1.CreateActivityDto !== "undefined" && create_activity_dto_1.CreateActivityDto) === "function" ? _f : Object]),
    tslib_1.__metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], ActivitiesController.prototype, "createActivity", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Activity id not found' }),
    (0, swagger_1.ApiConflictResponse)({
        description: 'Activity with same name already exists for project',
    }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'activityId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Patch)(':activityId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_h = typeof Request !== "undefined" && Request) === "function" ? _h : Object, typeof (_j = typeof update_activity_params_1.UpdateActivityParams !== "undefined" && update_activity_params_1.UpdateActivityParams) === "function" ? _j : Object, typeof (_k = typeof update_activity_dto_1.UpdateActivityDto !== "undefined" && update_activity_dto_1.UpdateActivityDto) === "function" ? _k : Object]),
    tslib_1.__metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], ActivitiesController.prototype, "updateActivity", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Activity id not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'activityId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Delete)(':activityId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_m = typeof Request !== "undefined" && Request) === "function" ? _m : Object, typeof (_o = typeof delete_activity_params_1.DeleteActivityParams !== "undefined" && delete_activity_params_1.DeleteActivityParams) === "function" ? _o : Object]),
    tslib_1.__metadata("design:returntype", typeof (_p = typeof Promise !== "undefined" && Promise) === "function" ? _p : Object)
], ActivitiesController.prototype, "deleteActivity", null);
ActivitiesController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Activities'),
    (0, common_1.Controller)('activities'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof activities_service_1.ActivitiesService !== "undefined" && activities_service_1.ActivitiesService) === "function" ? _a : Object, typeof (_b = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _b : Object])
], ActivitiesController);
exports.ActivitiesController = ActivitiesController;


/***/ }),
/* 81 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Activity = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
class Activity {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", String)
], Activity.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", String)
], Activity.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ActivityStatus !== "undefined" && models_1.ActivityStatus) === "function" ? _a : Object)
], Activity.prototype, "status", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", String)
], Activity.prototype, "clientId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    tslib_1.__metadata("design:type", String)
], Activity.prototype, "projectId", void 0);
exports.Activity = Activity;


/***/ }),
/* 82 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetActivitiesQueryParams = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
const class_validator_1 = __webpack_require__(56);
class GetActivitiesQueryParams {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        example: 'enabled',
        enum: models_1.activityStatusList,
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsIn)(models_1.activityStatusList),
    tslib_1.__metadata("design:type", Object)
], GetActivitiesQueryParams.prototype, "status", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        type: String,
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", Object)
], GetActivitiesQueryParams.prototype, "clientId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        type: String,
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", Object)
], GetActivitiesQueryParams.prototype, "projectId", void 0);
exports.GetActivitiesQueryParams = GetActivitiesQueryParams;


/***/ }),
/* 83 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateActivityDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const models_1 = __webpack_require__(17);
const is_not_blank_string_validator_1 = __webpack_require__(58);
class CreateActivityDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Implementation' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateActivityDto.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], CreateActivityDto.prototype, "projectId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.activityStatusList,
        example: 'enabled',
    }),
    (0, class_validator_1.IsIn)(models_1.activityStatusList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ActivityStatus !== "undefined" && models_1.ActivityStatus) === "function" ? _a : Object)
], CreateActivityDto.prototype, "status", void 0);
exports.CreateActivityDto = CreateActivityDto;


/***/ }),
/* 84 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateActivityParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class UpdateActivityParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], UpdateActivityParams.prototype, "activityId", void 0);
exports.UpdateActivityParams = UpdateActivityParams;


/***/ }),
/* 85 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateActivityDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const is_not_blank_string_validator_1 = __webpack_require__(58);
const models_1 = __webpack_require__(17);
class UpdateActivityDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Meeting' }),
    (0, class_validator_1.IsOptional)(),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], UpdateActivityDto.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.activityStatusList,
        example: 'enabled',
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsIn)(models_1.activityStatusList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.ActivityStatus !== "undefined" && models_1.ActivityStatus) === "function" ? _a : Object)
], UpdateActivityDto.prototype, "status", void 0);
exports.UpdateActivityDto = UpdateActivityDto;


/***/ }),
/* 86 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DeleteActivityParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class DeleteActivityParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], DeleteActivityParams.prototype, "activityId", void 0);
exports.DeleteActivityParams = DeleteActivityParams;


/***/ }),
/* 87 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HealthModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const health_controller_1 = __webpack_require__(88);
const health_service_1 = __webpack_require__(89);
let HealthModule = class HealthModule {
};
HealthModule = tslib_1.__decorate([
    (0, common_1.Module)({
        imports: [],
        controllers: [health_controller_1.HealthController],
        providers: [health_service_1.HealthService],
    })
], HealthModule);
exports.HealthModule = HealthModule;


/***/ }),
/* 88 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HealthController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const health_service_1 = __webpack_require__(89);
const swagger_1 = __webpack_require__(5);
const skip_auth_decorator_1 = __webpack_require__(38);
let HealthController = class HealthController {
    constructor(healthService) {
        this.healthService = healthService;
    }
    getHello() {
        return this.healthService.getHello();
    }
};
tslib_1.__decorate([
    (0, skip_auth_decorator_1.SkipAuth)(),
    (0, common_1.Get)('hello'),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", []),
    tslib_1.__metadata("design:returntype", Object)
], HealthController.prototype, "getHello", null);
HealthController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Health'),
    (0, common_1.Controller)('health'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof health_service_1.HealthService !== "undefined" && health_service_1.HealthService) === "function" ? _a : Object])
], HealthController);
exports.HealthController = HealthController;


/***/ }),
/* 89 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HealthService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
let HealthService = class HealthService {
    constructor(configService) {
        this.configService = configService;
    }
    getHello() {
        return {
            name: 'HRMS API service',
            isProduction: this.configService.get('isProduction'),
            organization: this.configService.get('organization', { infer: true })
                .name,
        };
    }
};
HealthService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], HealthService);
exports.HealthService = HealthService;


/***/ }),
/* 90 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.loadConfig = void 0;
const loadConfig = () => {
    const config = {
        databaseUri: process.env.DATABASE_URI || 'mongodb://127.0.0.1:27017/hrms',
        isProduction: process.env.NODE_ENV === 'production',
        logFileMaximum: process.env.LOG_FILE_MAXIMUM || '30d',
        logFilePath: process.env.LOG_FILE_PATH || './logs',
        jwtAccessExpiresInMinutes: process.env.JWT_ACCESS_EXPIRES_IN_MINUTES || '60',
        jwtAccessSecret: process.env.JWT_ACCESS_SECRET || 'secret_access',
        jwtRefreshExpiresInMinutes: process.env.JWT_REFRESH_EXPIRES_IN_MINUTES || '1440',
        jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'secret_refresh',
        organization: {
            name: process.env.ORGANIZATION_NAME || 'Orbital Technologies Inc.',
        },
        useHttps: process.env.USE_HTTPS === 'true',
    };
    return config;
};
exports.loadConfig = loadConfig;


/***/ }),
/* 91 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MongooseConfigService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
let MongooseConfigService = class MongooseConfigService {
    constructor(configService) {
        this.configService = configService;
    }
    createMongooseOptions() {
        return {
            uri: this.configService.get('databaseUri', { infer: true }),
        };
    }
};
MongooseConfigService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], MongooseConfigService);
exports.MongooseConfigService = MongooseConfigService;


/***/ }),
/* 92 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const user_controller_1 = __webpack_require__(93);
const users_service_1 = __webpack_require__(48);
const users_assembler_1 = __webpack_require__(54);
const user_record_helper_1 = __webpack_require__(62);
const clients_service_1 = __webpack_require__(50);
const projects_service_1 = __webpack_require__(49);
const activities_service_1 = __webpack_require__(52);
const timesheet_events_service_1 = __webpack_require__(94);
const timesheet_events_assembler_1 = __webpack_require__(106);
const work_summaries_service_1 = __webpack_require__(109);
const work_summaries_assembler_1 = __webpack_require__(113);
const user_schema_1 = __webpack_require__(16);
const client_schema_1 = __webpack_require__(29);
const project_schema_1 = __webpack_require__(30);
const activity_schema_1 = __webpack_require__(28);
const timesheet_event_schema_1 = __webpack_require__(51);
const work_summary_schema_1 = __webpack_require__(110);
let UserModule = class UserModule {
};
UserModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [user_controller_1.UserController],
        providers: [
            users_service_1.UsersService,
            users_assembler_1.UsersAssembler,
            user_record_helper_1.UserRecordHelper,
            clients_service_1.ClientsService,
            projects_service_1.ProjectsService,
            activities_service_1.ActivitiesService,
            timesheet_events_service_1.TimesheetEventsService,
            timesheet_events_assembler_1.TimesheetEventsAssembler,
            work_summaries_service_1.WorkSummariesService,
            work_summaries_assembler_1.WorkSummariesAssembler,
        ],
        imports: [
            mongoose_1.MongooseModule.forFeature([{ name: user_schema_1.UserRecord.name, schema: user_schema_1.UserSchema }]),
            mongoose_1.MongooseModule.forFeature([
                { name: client_schema_1.ClientRecord.name, schema: client_schema_1.ClientSchema },
            ]),
            mongoose_1.MongooseModule.forFeature([
                { name: project_schema_1.ProjectRecord.name, schema: project_schema_1.ProjectSchema },
            ]),
            mongoose_1.MongooseModule.forFeature([
                { name: activity_schema_1.ActivityRecord.name, schema: activity_schema_1.ActivitySchema },
            ]),
            mongoose_1.MongooseModule.forFeature([
                { name: timesheet_event_schema_1.TimesheetEventRecord.name, schema: timesheet_event_schema_1.TimesheetEventSchema },
            ]),
            mongoose_1.MongooseModule.forFeature([
                { name: work_summary_schema_1.WorkSummaryRecord.name, schema: work_summary_schema_1.WorkSummarySchema },
            ]),
        ],
    })
], UserModule);
exports.UserModule = UserModule;


/***/ }),
/* 93 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t, _u, _v, _w, _x, _y, _z, _0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
const express_1 = __webpack_require__(36);
const api_helper_1 = __webpack_require__(31);
const timesheet_events_service_1 = __webpack_require__(94);
const create_timesheet_event_dto_1 = __webpack_require__(99);
const users_assembler_1 = __webpack_require__(54);
const users_service_1 = __webpack_require__(48);
const assert_user_exists_1 = __webpack_require__(32);
const update_timesheet_event_dto_1 = __webpack_require__(102);
const update_timesheet_event_params_1 = __webpack_require__(103);
const timesheet_event_1 = __webpack_require__(104);
const get_timesheet_events_query_params_1 = __webpack_require__(105);
const timesheet_events_assembler_1 = __webpack_require__(106);
const delete_timesheet_event_params_1 = __webpack_require__(107);
const work_summary_1 = __webpack_require__(108);
const work_summaries_service_1 = __webpack_require__(109);
const work_summaries_assembler_1 = __webpack_require__(113);
const get_work_summaries_query_params_1 = __webpack_require__(114);
const create_work_summary_dto_1 = __webpack_require__(115);
const update_work_summary_dto_1 = __webpack_require__(116);
const update_work_summary_params_1 = __webpack_require__(117);
const delete_work_summary_params_1 = __webpack_require__(118);
const change_password_dto_1 = __webpack_require__(119);
let UserController = class UserController {
    constructor(usersService, usersAssembler, timesheetEventService, timesheetEventsAssembler, workSummaryService, workSummariesAssembler) {
        this.usersService = usersService;
        this.usersAssembler = usersAssembler;
        this.timesheetEventService = timesheetEventService;
        this.timesheetEventsAssembler = timesheetEventsAssembler;
        this.workSummaryService = workSummaryService;
        this.workSummariesAssembler = workSummariesAssembler;
    }
    getUserInformation(request) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            return this.usersAssembler.assembleUser(userRecord);
        });
    }
    getTimesheetEvents(request, { startDate, endDate }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            const timesheetEventRecords = yield this.timesheetEventService.getTimesheetEvents(userRecord, startDate, endDate);
            return this.timesheetEventsAssembler.assembleEvents(timesheetEventRecords);
        });
    }
    createTimesheetEvent(request, createEventDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            const id = yield this.timesheetEventService.createTimesheetEvent(userRecord, createEventDto);
            return { id };
        });
    }
    updateTimesheetEvent(request, { eventId }, updateEventDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            yield this.timesheetEventService.updateTimesheetEvent(eventId, userRecord, updateEventDto);
        });
    }
    deleteTimesheetEvent(request, { eventId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            yield this.timesheetEventService.deleteTimesheetEvent(eventId, userRecord);
        });
    }
    getWorkSummaries(request, { startDate, endDate, projectId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            const workSummaryRecords = yield this.workSummaryService.getWorkSummaries(userRecord, startDate, endDate, projectId);
            return this.workSummariesAssembler.assembleWorkSummaries(workSummaryRecords);
        });
    }
    createWorkSummary(request, createSummaryDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            const id = yield this.workSummaryService.createWorkSummary(userRecord, createSummaryDto);
            return { id };
        });
    }
    updateWorkSummary(request, { workSummaryId }, updateWorkSummaryDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            yield this.workSummaryService.updateWorkSummary(workSummaryId, userRecord, updateWorkSummaryDto);
        });
    }
    deleteWorkSummary(request, { workSummaryId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            yield this.workSummaryService.deleteWorkSummary(workSummaryId, userRecord);
        });
    }
    changePassword(request, { currentPassword, newPassword }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            yield this.usersService.changeUserPassword(userId, currentPassword, newPassword);
        });
    }
};
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({ description: 'Success', type: models_1.User }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Get)(),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_g = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _g : Object]),
    tslib_1.__metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
], UserController.prototype, "getUserInformation", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({
        description: 'Success',
        type: timesheet_event_1.TimesheetEvent,
        isArray: true,
    }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Get)('timesheet-events'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Query)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_j = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _j : Object, typeof (_k = typeof get_timesheet_events_query_params_1.GetTimesheetEventsQueryParams !== "undefined" && get_timesheet_events_query_params_1.GetTimesheetEventsQueryParams) === "function" ? _k : Object]),
    tslib_1.__metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], UserController.prototype, "getTimesheetEvents", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiCreatedResponse)({ description: 'Created', type: String }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Post)('timesheet-events'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_m = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _m : Object, typeof (_o = typeof create_timesheet_event_dto_1.CreateTimesheetEventDto !== "undefined" && create_timesheet_event_dto_1.CreateTimesheetEventDto) === "function" ? _o : Object]),
    tslib_1.__metadata("design:returntype", typeof (_p = typeof Promise !== "undefined" && Promise) === "function" ? _p : Object)
], UserController.prototype, "createTimesheetEvent", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Not found' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'eventId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Put)('timesheet-events/:eventId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_q = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _q : Object, typeof (_r = typeof update_timesheet_event_params_1.UpdateTimesheetEventParams !== "undefined" && update_timesheet_event_params_1.UpdateTimesheetEventParams) === "function" ? _r : Object, typeof (_s = typeof update_timesheet_event_dto_1.UpdateTimesheetEventDto !== "undefined" && update_timesheet_event_dto_1.UpdateTimesheetEventDto) === "function" ? _s : Object]),
    tslib_1.__metadata("design:returntype", typeof (_t = typeof Promise !== "undefined" && Promise) === "function" ? _t : Object)
], UserController.prototype, "updateTimesheetEvent", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Not found' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'eventId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Delete)('timesheet-events/:eventId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_u = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _u : Object, typeof (_v = typeof delete_timesheet_event_params_1.DeleteTimesheetEventParams !== "undefined" && delete_timesheet_event_params_1.DeleteTimesheetEventParams) === "function" ? _v : Object]),
    tslib_1.__metadata("design:returntype", typeof (_w = typeof Promise !== "undefined" && Promise) === "function" ? _w : Object)
], UserController.prototype, "deleteTimesheetEvent", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({
        description: 'Success',
        type: work_summary_1.WorkSummary,
        isArray: true,
    }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Get)('work-summaries'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Query)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_x = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _x : Object, typeof (_y = typeof get_work_summaries_query_params_1.GetWorkSummariesQueryParams !== "undefined" && get_work_summaries_query_params_1.GetWorkSummariesQueryParams) === "function" ? _y : Object]),
    tslib_1.__metadata("design:returntype", typeof (_z = typeof Promise !== "undefined" && Promise) === "function" ? _z : Object)
], UserController.prototype, "getWorkSummaries", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiCreatedResponse)({ description: 'Created', type: String }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Post)('work-summaries'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_0 = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _0 : Object, typeof (_1 = typeof create_work_summary_dto_1.CreateWorkSummaryDto !== "undefined" && create_work_summary_dto_1.CreateWorkSummaryDto) === "function" ? _1 : Object]),
    tslib_1.__metadata("design:returntype", typeof (_2 = typeof Promise !== "undefined" && Promise) === "function" ? _2 : Object)
], UserController.prototype, "createWorkSummary", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Not found' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'workSummaryId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Patch)('work-summaries/:workSummaryId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_3 = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _3 : Object, typeof (_4 = typeof update_work_summary_params_1.UpdateWorkSummaryParams !== "undefined" && update_work_summary_params_1.UpdateWorkSummaryParams) === "function" ? _4 : Object, typeof (_5 = typeof update_work_summary_dto_1.UpdateWorkSummaryDto !== "undefined" && update_work_summary_dto_1.UpdateWorkSummaryDto) === "function" ? _5 : Object]),
    tslib_1.__metadata("design:returntype", typeof (_6 = typeof Promise !== "undefined" && Promise) === "function" ? _6 : Object)
], UserController.prototype, "updateWorkSummary", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Not found' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'workSummaryId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Delete)('work-summaries/:workSummaryId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_7 = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _7 : Object, typeof (_8 = typeof delete_work_summary_params_1.DeleteWorkSummaryParams !== "undefined" && delete_work_summary_params_1.DeleteWorkSummaryParams) === "function" ? _8 : Object]),
    tslib_1.__metadata("design:returntype", typeof (_9 = typeof Promise !== "undefined" && Promise) === "function" ? _9 : Object)
], UserController.prototype, "deleteWorkSummary", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Put)('password'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_10 = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _10 : Object, typeof (_11 = typeof change_password_dto_1.ChangePasswordDto !== "undefined" && change_password_dto_1.ChangePasswordDto) === "function" ? _11 : Object]),
    tslib_1.__metadata("design:returntype", typeof (_12 = typeof Promise !== "undefined" && Promise) === "function" ? _12 : Object)
], UserController.prototype, "changePassword", null);
UserController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Current user'),
    (0, common_1.Controller)('user'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof users_assembler_1.UsersAssembler !== "undefined" && users_assembler_1.UsersAssembler) === "function" ? _b : Object, typeof (_c = typeof timesheet_events_service_1.TimesheetEventsService !== "undefined" && timesheet_events_service_1.TimesheetEventsService) === "function" ? _c : Object, typeof (_d = typeof timesheet_events_assembler_1.TimesheetEventsAssembler !== "undefined" && timesheet_events_assembler_1.TimesheetEventsAssembler) === "function" ? _d : Object, typeof (_e = typeof work_summaries_service_1.WorkSummariesService !== "undefined" && work_summaries_service_1.WorkSummariesService) === "function" ? _e : Object, typeof (_f = typeof work_summaries_assembler_1.WorkSummariesAssembler !== "undefined" && work_summaries_assembler_1.WorkSummariesAssembler) === "function" ? _f : Object])
], UserController);
exports.UserController = UserController;


/***/ }),
/* 94 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TimesheetEventsService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const timesheet_event_schema_1 = __webpack_require__(51);
const user_record_helper_1 = __webpack_require__(62);
const duration_validation_helper_1 = __webpack_require__(95);
const activity_validation_helper_1 = __webpack_require__(96);
const event_validation_helper_1 = __webpack_require__(97);
const activities_service_1 = __webpack_require__(52);
const projects_service_1 = __webpack_require__(49);
const date_utils_validator_1 = __webpack_require__(98);
let TimesheetEventsService = class TimesheetEventsService {
    constructor(timesheetEventModel, userRecordHelper, activitiesService, projectsService) {
        this.timesheetEventModel = timesheetEventModel;
        this.userRecordHelper = userRecordHelper;
        this.activitiesService = activitiesService;
        this.projectsService = projectsService;
    }
    getTimesheetEvents(userRecord, startDate, endDate) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            date_utils_validator_1.DateUtils.validateDateRange(startDate, endDate);
            return yield this.timesheetEventModel
                .find({
                user: userRecord._id,
                date: {
                    $gte: startDate,
                    $lte: endDate,
                },
            })
                .exec();
        });
    }
    createTimesheetEvent(userRecord, createEventDto) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = userRecord._id;
            const { eventType, date: eventDate, durationMinutes: eventMinutes, comment, } = createEventDto;
            const assignedActivity = (0, activity_validation_helper_1.validateActivityId)(userRecord, this.userRecordHelper, eventType, createEventDto.activityId);
            yield (0, duration_validation_helper_1.validateTotalDuration)(this.timesheetEventModel, userId, eventDate, eventMinutes);
            const projectId = yield this.activitiesService.getActivityProjectId(assignedActivity === null || assignedActivity === void 0 ? void 0 : assignedActivity._id);
            const clientId = yield this.projectsService.getProjectClientId(projectId);
            const event = new this.timesheetEventModel({
                user: userId,
                date: eventDate,
                durationMinutes: eventMinutes,
                eventType,
                comment,
                activity: assignedActivity === null || assignedActivity === void 0 ? void 0 : assignedActivity._id,
                project: projectId,
                client: clientId,
            });
            const eventId = (_a = (yield event.save())) === null || _a === void 0 ? void 0 : _a.id;
            if (!eventId) {
                throw new common_1.InternalServerErrorException('Failed to save new timesheet event');
            }
            return eventId;
        });
    }
    updateTimesheetEvent(eventId, userRecord, updateEventDto) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = userRecord._id;
            const existingEvent = yield (0, event_validation_helper_1.validateEventId)(this.timesheetEventModel, userId, eventId);
            const { eventType, date: updateEventDate, durationMinutes: updateEventMinutes, comment, } = updateEventDto;
            const assignedActivity = (0, activity_validation_helper_1.validateActivityId)(userRecord, this.userRecordHelper, eventType, updateEventDto.activityId);
            const eventMinutesDelta = existingEvent.date === updateEventDate
                ? updateEventMinutes - existingEvent.durationMinutes
                : updateEventMinutes;
            yield (0, duration_validation_helper_1.validateTotalDuration)(this.timesheetEventModel, userId, updateEventDate, eventMinutesDelta);
            const projectId = yield this.activitiesService.getActivityProjectId(assignedActivity === null || assignedActivity === void 0 ? void 0 : assignedActivity._id);
            const clientId = yield this.projectsService.getProjectClientId(projectId);
            yield existingEvent.updateOne({
                date: updateEventDate,
                durationMinutes: updateEventMinutes,
                eventType,
                comment,
                activity: (_a = assignedActivity === null || assignedActivity === void 0 ? void 0 : assignedActivity._id) !== null && _a !== void 0 ? _a : null,
                project: projectId !== null && projectId !== void 0 ? projectId : null,
                client: clientId !== null && clientId !== void 0 ? clientId : null,
            });
        });
    }
    deleteTimesheetEvent(eventId, userRecord) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = userRecord._id;
            const existingEvent = yield (0, event_validation_helper_1.validateEventId)(this.timesheetEventModel, userId, eventId);
            yield existingEvent.deleteOne();
        });
    }
};
TimesheetEventsService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(timesheet_event_schema_1.TimesheetEventRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object, typeof (_b = typeof user_record_helper_1.UserRecordHelper !== "undefined" && user_record_helper_1.UserRecordHelper) === "function" ? _b : Object, typeof (_c = typeof activities_service_1.ActivitiesService !== "undefined" && activities_service_1.ActivitiesService) === "function" ? _c : Object, typeof (_d = typeof projects_service_1.ProjectsService !== "undefined" && projects_service_1.ProjectsService) === "function" ? _d : Object])
], TimesheetEventsService);
exports.TimesheetEventsService = TimesheetEventsService;


/***/ }),
/* 95 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.validateTotalDuration = exports.maxTotalDurationMinutes = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
exports.maxTotalDurationMinutes = 24 * 60;
const validateTotalDuration = (timesheetEventModel, userId, eventDate, eventMinutes) => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    const durationTotalMinutes = yield sumDurationMinutesForDate(timesheetEventModel, userId, eventDate);
    if (durationTotalMinutes + eventMinutes > exports.maxTotalDurationMinutes) {
        throw new common_1.BadRequestException(`Total duration for all events for user '${userId}' on ${eventDate} exceeds 24 hours.`);
    }
});
exports.validateTotalDuration = validateTotalDuration;
const sumDurationMinutesForDate = (timesheetEventModel, userId, eventDate) => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    const eventsForDate = yield timesheetEventModel
        .find({
        user: userId,
        date: eventDate,
    })
        .exec();
    return eventsForDate.reduce((accumulator, { durationMinutes }) => accumulator + durationMinutes, 0);
});


/***/ }),
/* 96 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.validateActivityId = void 0;
const common_1 = __webpack_require__(7);
const validateActivityId = (userRecord, userRecordHelper, eventType, activityId) => {
    if (eventType !== 'work') {
        return undefined;
    }
    const assignedActivity = activityId
        ? userRecordHelper.getAssignedActivity(userRecord, activityId)
        : undefined;
    if (!assignedActivity) {
        throw new common_1.BadRequestException(`activityId '${activityId}' not available for user '${userRecord._id}'`);
    }
    return assignedActivity;
};
exports.validateActivityId = validateActivityId;


/***/ }),
/* 97 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.validateEventId = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const validateEventId = (timesheetEventModel, userId, eventId) => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    const event = yield timesheetEventModel.findById(eventId).exec();
    if (!event) {
        throw new common_1.NotFoundException(`Could not find timesheet event for '${eventId}'`);
    }
    if (!event.user._id.equals(userId)) {
        throw new common_1.BadRequestException(`Timesheet event '${eventId}' does not belong to user '${userId}'`);
    }
    return event;
});
exports.validateEventId = validateEventId;


/***/ }),
/* 98 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DateUtils = void 0;
const common_1 = __webpack_require__(7);
class DateUtils {
    static validateDateRange(startDate, endDate) {
        if (new Date(endDate) < new Date(startDate)) {
            throw new common_1.BadRequestException('End date must be on or after start date');
        }
    }
}
exports.DateUtils = DateUtils;


/***/ }),
/* 99 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateTimesheetEventDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const models_1 = __webpack_require__(17);
const is_date_only_string_validator_1 = __webpack_require__(100);
const is_duration_validator_1 = __webpack_require__(101);
class CreateTimesheetEventDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: new Date().toISOString().split('T')[0] }),
    (0, is_date_only_string_validator_1.IsDateOnlyString)(),
    tslib_1.__metadata("design:type", String)
], CreateTimesheetEventDto.prototype, "date", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 30 }),
    (0, is_duration_validator_1.IsDuration)(),
    tslib_1.__metadata("design:type", Number)
], CreateTimesheetEventDto.prototype, "durationMinutes", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.timesheetEventTypeList,
        example: 'work',
    }),
    (0, class_validator_1.IsIn)(models_1.timesheetEventTypeList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.TimesheetEventType !== "undefined" && models_1.TimesheetEventType) === "function" ? _a : Object)
], CreateTimesheetEventDto.prototype, "eventType", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.ValidateIf)((o) => o.eventType === 'work'),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], CreateTimesheetEventDto.prototype, "activityId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], CreateTimesheetEventDto.prototype, "comment", void 0);
exports.CreateTimesheetEventDto = CreateTimesheetEventDto;


/***/ }),
/* 100 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IsDateOnlyString = exports.IsDateOnlyStringValidator = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
let IsDateOnlyStringValidator = class IsDateOnlyStringValidator {
    validate(date) {
        const isFormatValid = !!(date === null || date === void 0 ? void 0 : date.match(/^\d{4}-\d{2}-\d{2}$/));
        return isFormatValid && (0, class_validator_1.isISO8601)(date, { strict: true });
    }
    defaultMessage({ property }) {
        return `${property} must be a valid ISO date (yyyy-mm-dd)`;
    }
};
IsDateOnlyStringValidator = tslib_1.__decorate([
    (0, class_validator_1.ValidatorConstraint)({ name: 'isDateOnlyString', async: false })
], IsDateOnlyStringValidator);
exports.IsDateOnlyStringValidator = IsDateOnlyStringValidator;
function IsDateOnlyString(validationOptions) {
    return function (object, propertyName) {
        (0, class_validator_1.registerDecorator)({
            target: object.constructor,
            propertyName,
            options: validationOptions,
            constraints: [],
            validator: IsDateOnlyStringValidator,
        });
    };
}
exports.IsDateOnlyString = IsDateOnlyString;


/***/ }),
/* 101 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IsDuration = exports.IsDurationValidator = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
const maxDurationMinutes = 24 * 60;
let IsDurationValidator = class IsDurationValidator {
    validate(duration) {
        return ((0, class_validator_1.isInt)(duration) && (0, class_validator_1.min)(duration, 0) && (0, class_validator_1.max)(duration, maxDurationMinutes));
    }
    defaultMessage({ property }) {
        return `${property} must be numeric and not less than 0 or greater than 24 hours`;
    }
};
IsDurationValidator = tslib_1.__decorate([
    (0, class_validator_1.ValidatorConstraint)({ name: 'isDuration', async: false })
], IsDurationValidator);
exports.IsDurationValidator = IsDurationValidator;
function IsDuration(validationOptions) {
    return function (object, propertyName) {
        (0, class_validator_1.registerDecorator)({
            target: object.constructor,
            propertyName,
            options: validationOptions,
            constraints: [],
            validator: IsDurationValidator,
        });
    };
}
exports.IsDuration = IsDuration;


/***/ }),
/* 102 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateTimesheetEventDto = void 0;
const create_timesheet_event_dto_1 = __webpack_require__(99);
class UpdateTimesheetEventDto extends create_timesheet_event_dto_1.CreateTimesheetEventDto {
}
exports.UpdateTimesheetEventDto = UpdateTimesheetEventDto;


/***/ }),
/* 103 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateTimesheetEventParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class UpdateTimesheetEventParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], UpdateTimesheetEventParams.prototype, "eventId", void 0);
exports.UpdateTimesheetEventParams = UpdateTimesheetEventParams;


/***/ }),
/* 104 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TimesheetEvent = exports.TimesheetEventContext = void 0;
const tslib_1 = __webpack_require__(2);
const models_1 = __webpack_require__(17);
const swagger_1 = __webpack_require__(5);
class TimesheetEventContext {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetEventContext.prototype, "activityId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetEventContext.prototype, "projectId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetEventContext.prototype, "clientId", void 0);
exports.TimesheetEventContext = TimesheetEventContext;
class TimesheetEvent {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetEvent.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetEvent.prototype, "userId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetEvent.prototype, "date", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", Number)
], TimesheetEvent.prototype, "durationMinutes", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.TimesheetEventType !== "undefined" && models_1.TimesheetEventType) === "function" ? _a : Object)
], TimesheetEvent.prototype, "eventType", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetEvent.prototype, "comment", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", TimesheetEventContext)
], TimesheetEvent.prototype, "context", void 0);
exports.TimesheetEvent = TimesheetEvent;


/***/ }),
/* 105 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetTimesheetEventsQueryParams = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const is_date_only_string_validator_1 = __webpack_require__(100);
class GetTimesheetEventsQueryParams {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: new Date().toISOString().split('T')[0] }),
    (0, is_date_only_string_validator_1.IsDateOnlyString)(),
    tslib_1.__metadata("design:type", String)
], GetTimesheetEventsQueryParams.prototype, "startDate", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: new Date().toISOString().split('T')[0] }),
    (0, is_date_only_string_validator_1.IsDateOnlyString)(),
    tslib_1.__metadata("design:type", String)
], GetTimesheetEventsQueryParams.prototype, "endDate", void 0);
exports.GetTimesheetEventsQueryParams = GetTimesheetEventsQueryParams;


/***/ }),
/* 106 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TimesheetEventsAssembler = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
let TimesheetEventsAssembler = class TimesheetEventsAssembler {
    assembleEvents(timesheetEventRecords) {
        return timesheetEventRecords.map((eventRecord) => {
            var _a, _b;
            const context = eventRecord.activity
                ? {
                    activityId: eventRecord.activity._id.toString(),
                    projectId: (_a = eventRecord.project) === null || _a === void 0 ? void 0 : _a._id.toString(),
                    clientId: (_b = eventRecord.client) === null || _b === void 0 ? void 0 : _b._id.toString(),
                }
                : undefined;
            return {
                id: eventRecord._id.toString(),
                userId: eventRecord.user._id.toString(),
                date: eventRecord.date,
                eventType: eventRecord.eventType,
                durationMinutes: eventRecord.durationMinutes,
                comment: eventRecord.comment,
                context,
            };
        });
    }
};
TimesheetEventsAssembler = tslib_1.__decorate([
    (0, common_1.Injectable)()
], TimesheetEventsAssembler);
exports.TimesheetEventsAssembler = TimesheetEventsAssembler;


/***/ }),
/* 107 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DeleteTimesheetEventParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class DeleteTimesheetEventParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], DeleteTimesheetEventParams.prototype, "eventId", void 0);
exports.DeleteTimesheetEventParams = DeleteTimesheetEventParams;


/***/ }),
/* 108 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WorkSummary = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
class WorkSummary {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], WorkSummary.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], WorkSummary.prototype, "clientId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], WorkSummary.prototype, "projectId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], WorkSummary.prototype, "date", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], WorkSummary.prototype, "summary", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    tslib_1.__metadata("design:type", Boolean)
], WorkSummary.prototype, "isSREDEligible", void 0);
exports.WorkSummary = WorkSummary;


/***/ }),
/* 109 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WorkSummariesService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const work_summary_schema_1 = __webpack_require__(110);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const date_utils_validator_1 = __webpack_require__(98);
const user_record_helper_1 = __webpack_require__(62);
const project_validation_helper_1 = __webpack_require__(111);
const summary_validation_helper_1 = __webpack_require__(112);
const projects_service_1 = __webpack_require__(49);
let WorkSummariesService = class WorkSummariesService {
    constructor(workSummaryModel, projectsService, userRecordHelper) {
        this.workSummaryModel = workSummaryModel;
        this.projectsService = projectsService;
        this.userRecordHelper = userRecordHelper;
    }
    getWorkSummaries(userRecord, startDate, endDate, projectId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            date_utils_validator_1.DateUtils.validateDateRange(startDate, endDate);
            const query = {
                user: userRecord._id,
                date: {
                    $gte: startDate,
                    $lte: endDate,
                },
            };
            if (projectId) {
                query.project = projectId;
            }
            return yield this.workSummaryModel.find(query).exec();
        });
    }
    createWorkSummary(userRecord, createSummaryDto) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = userRecord._id;
            const { date, projectId, summary, isSREDEligible } = createSummaryDto;
            const assignedProject = (0, project_validation_helper_1.validateProjectId)(userRecord, this.userRecordHelper, projectId);
            const clientId = yield this.projectsService.getProjectClientId(projectId);
            const workSummary = new this.workSummaryModel({
                user: userId,
                date,
                client: clientId,
                project: assignedProject === null || assignedProject === void 0 ? void 0 : assignedProject._id,
                summary,
                isSREDEligible,
            });
            const workSummaryId = (_a = (yield workSummary.save())) === null || _a === void 0 ? void 0 : _a.id;
            if (!workSummaryId) {
                throw new common_1.InternalServerErrorException('Failed to save new work summary');
            }
            return workSummaryId;
        });
    }
    updateWorkSummary(workSummaryId, userRecord, updateWorkSummaryDto) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = userRecord._id;
            const { summary, isSREDEligible } = updateWorkSummaryDto;
            const existingSummary = yield (0, summary_validation_helper_1.validateWorkSummaryId)(this.workSummaryModel, userId, workSummaryId);
            yield existingSummary.updateOne({
                summary,
                isSREDEligible,
            });
        });
    }
    deleteWorkSummary(workSummaryId, userRecord) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = userRecord._id;
            const existingSummary = yield (0, summary_validation_helper_1.validateWorkSummaryId)(this.workSummaryModel, userId, workSummaryId);
            yield existingSummary.deleteOne();
        });
    }
};
WorkSummariesService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(work_summary_schema_1.WorkSummaryRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object, typeof (_b = typeof projects_service_1.ProjectsService !== "undefined" && projects_service_1.ProjectsService) === "function" ? _b : Object, typeof (_c = typeof user_record_helper_1.UserRecordHelper !== "undefined" && user_record_helper_1.UserRecordHelper) === "function" ? _c : Object])
], WorkSummariesService);
exports.WorkSummariesService = WorkSummariesService;


/***/ }),
/* 110 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WorkSummarySchema = exports.WorkSummaryRecord = void 0;
const tslib_1 = __webpack_require__(2);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const client_schema_1 = __webpack_require__(29);
const project_schema_1 = __webpack_require__(30);
const user_schema_1 = __webpack_require__(16);
let WorkSummaryRecord = class WorkSummaryRecord {
};
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.SchemaTypes.ObjectId, ref: user_schema_1.UserRecord.name, required: true }),
    tslib_1.__metadata("design:type", typeof (_a = typeof user_schema_1.UserRecord !== "undefined" && user_schema_1.UserRecord) === "function" ? _a : Object)
], WorkSummaryRecord.prototype, "user", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.SchemaTypes.ObjectId, ref: client_schema_1.ClientRecord.name, required: true }),
    tslib_1.__metadata("design:type", typeof (_b = typeof client_schema_1.ClientRecord !== "undefined" && client_schema_1.ClientRecord) === "function" ? _b : Object)
], WorkSummaryRecord.prototype, "client", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.SchemaTypes.ObjectId, ref: project_schema_1.ProjectRecord.name, required: true }),
    tslib_1.__metadata("design:type", typeof (_c = typeof project_schema_1.ProjectRecord !== "undefined" && project_schema_1.ProjectRecord) === "function" ? _c : Object)
], WorkSummaryRecord.prototype, "project", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], WorkSummaryRecord.prototype, "date", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], WorkSummaryRecord.prototype, "summary", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: false }),
    tslib_1.__metadata("design:type", Boolean)
], WorkSummaryRecord.prototype, "isSREDEligible", void 0);
WorkSummaryRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'workSummaries' })
], WorkSummaryRecord);
exports.WorkSummaryRecord = WorkSummaryRecord;
const WorkSummarySchema = mongoose_1.SchemaFactory.createForClass(WorkSummaryRecord);
exports.WorkSummarySchema = WorkSummarySchema;


/***/ }),
/* 111 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.validateProjectId = void 0;
const common_1 = __webpack_require__(7);
const validateProjectId = (userRecord, userRecordHelper, projectId) => {
    const assignedProject = projectId
        ? userRecordHelper.getAssignedProject(userRecord, projectId)
        : undefined;
    if (!assignedProject) {
        throw new common_1.BadRequestException(`projectId '${projectId}' not available for user '${userRecord._id}'`);
    }
    return assignedProject;
};
exports.validateProjectId = validateProjectId;


/***/ }),
/* 112 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.validateWorkSummaryId = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const validateWorkSummaryId = (workSummaryModel, userId, workSummaryId) => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    const workSummary = yield workSummaryModel.findById(workSummaryId).exec();
    if (!workSummary) {
        throw new common_1.NotFoundException(`Could not find work summary for '${workSummaryId}'`);
    }
    if (!workSummary.user._id.equals(userId)) {
        throw new common_1.BadRequestException(`Work summary '${workSummaryId}' does not belong to user '${userId}'`);
    }
    return workSummary;
});
exports.validateWorkSummaryId = validateWorkSummaryId;


/***/ }),
/* 113 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WorkSummariesAssembler = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
let WorkSummariesAssembler = class WorkSummariesAssembler {
    assembleWorkSummaries(workSummaryRecord) {
        return workSummaryRecord.map((workSummaryRecord) => {
            return {
                id: workSummaryRecord._id.toString(),
                clientId: workSummaryRecord.client._id.toString(),
                projectId: workSummaryRecord.project._id.toString(),
                date: workSummaryRecord.date,
                summary: workSummaryRecord.summary,
                isSREDEligible: workSummaryRecord.isSREDEligible,
            };
        });
    }
};
WorkSummariesAssembler = tslib_1.__decorate([
    (0, common_1.Injectable)()
], WorkSummariesAssembler);
exports.WorkSummariesAssembler = WorkSummariesAssembler;


/***/ }),
/* 114 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetWorkSummariesQueryParams = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const is_date_only_string_validator_1 = __webpack_require__(100);
const class_validator_1 = __webpack_require__(56);
class GetWorkSummariesQueryParams {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        type: String,
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", Object)
], GetWorkSummariesQueryParams.prototype, "projectId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: new Date().toISOString().split('T')[0] }),
    (0, is_date_only_string_validator_1.IsDateOnlyString)(),
    tslib_1.__metadata("design:type", String)
], GetWorkSummariesQueryParams.prototype, "startDate", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: new Date().toISOString().split('T')[0] }),
    (0, is_date_only_string_validator_1.IsDateOnlyString)(),
    tslib_1.__metadata("design:type", String)
], GetWorkSummariesQueryParams.prototype, "endDate", void 0);
exports.GetWorkSummariesQueryParams = GetWorkSummariesQueryParams;


/***/ }),
/* 115 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateWorkSummaryDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const is_date_only_string_validator_1 = __webpack_require__(100);
const is_not_blank_string_validator_1 = __webpack_require__(58);
class CreateWorkSummaryDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: new Date().toISOString().split('T')[0] }),
    (0, is_date_only_string_validator_1.IsDateOnlyString)(),
    tslib_1.__metadata("design:type", String)
], CreateWorkSummaryDto.prototype, "date", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], CreateWorkSummaryDto.prototype, "projectId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateWorkSummaryDto.prototype, "summary", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", Boolean)
], CreateWorkSummaryDto.prototype, "isSREDEligible", void 0);
exports.CreateWorkSummaryDto = CreateWorkSummaryDto;


/***/ }),
/* 116 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateWorkSummaryDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const is_not_blank_string_validator_1 = __webpack_require__(58);
class UpdateWorkSummaryDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], UpdateWorkSummaryDto.prototype, "summary", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", Boolean)
], UpdateWorkSummaryDto.prototype, "isSREDEligible", void 0);
exports.UpdateWorkSummaryDto = UpdateWorkSummaryDto;


/***/ }),
/* 117 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateWorkSummaryParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class UpdateWorkSummaryParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], UpdateWorkSummaryParams.prototype, "workSummaryId", void 0);
exports.UpdateWorkSummaryParams = UpdateWorkSummaryParams;


/***/ }),
/* 118 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DeleteWorkSummaryParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class DeleteWorkSummaryParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], DeleteWorkSummaryParams.prototype, "workSummaryId", void 0);
exports.DeleteWorkSummaryParams = DeleteWorkSummaryParams;


/***/ }),
/* 119 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ChangePasswordDto = void 0;
const tslib_1 = __webpack_require__(2);
const is_not_blank_string_validator_1 = __webpack_require__(58);
const swagger_1 = __webpack_require__(5);
class ChangePasswordDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], ChangePasswordDto.prototype, "currentPassword", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], ChangePasswordDto.prototype, "newPassword", void 0);
exports.ChangePasswordDto = ChangePasswordDto;


/***/ }),
/* 120 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoggerMiddleware = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const nest_winston_1 = __webpack_require__(121);
let LoggerMiddleware = class LoggerMiddleware {
    constructor(logger) {
        this.logger = logger;
    }
    use(req, res, next) {
        const context = 'HTTP';
        const { method, originalUrl, body: requestBody } = req;
        const [oldWrite, oldEnd] = [res.write, res.end];
        const responseBodyBuffer = [];
        // Response message construction adapted from https://stackoverflow.com/a/58882269/7033700
        res.write = function (chunk, ...args) {
            responseBodyBuffer.push(Buffer.from(chunk));
            oldWrite.apply(res, [chunk, ...args]);
        };
        res.end = function (chunk, ...args) {
            if (chunk) {
                responseBodyBuffer.push(Buffer.from(chunk));
            }
            return oldEnd.apply(res, [chunk, ...args]);
        };
        res.on('close', () => {
            const { statusCode, statusMessage } = res;
            const maskedBody = this.maskSensitiveProperties(requestBody);
            const formattedMessage = `${method} ${originalUrl}; body: ${JSON.stringify(maskedBody)} - ${statusCode}, ${statusMessage}`;
            if (statusCode >= 400) {
                const errorMessage = this.buildErrorResponseMessage(responseBodyBuffer);
                this.logger.error(errorMessage
                    ? `${formattedMessage}; ${errorMessage}`
                    : formattedMessage, context);
            }
            else {
                this.logger.log(formattedMessage, context);
            }
        });
        next();
    }
    maskSensitiveProperties(body) {
        const sensitiveProperties = ['password', 'currentPassword', 'newPassword'];
        const maskedBody = Object.assign({}, body);
        sensitiveProperties.forEach((sensitiveProperty) => {
            if (sensitiveProperty in maskedBody) {
                maskedBody[sensitiveProperty] = '*****';
            }
        });
        return maskedBody;
    }
    buildErrorResponseMessage(responseBodyBuffer) {
        const responseBody = Buffer.concat(responseBodyBuffer).toString('utf8');
        if (!responseBody) {
            return '';
        }
        const bodyObject = JSON.parse(responseBody);
        const message = bodyObject.message || '';
        return Array.isArray(message) ? message.join('; ') : message;
    }
};
LoggerMiddleware = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, common_1.Inject)(nest_winston_1.WINSTON_MODULE_NEST_PROVIDER)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof common_1.LoggerService !== "undefined" && common_1.LoggerService) === "function" ? _a : Object])
], LoggerMiddleware);
exports.LoggerMiddleware = LoggerMiddleware;


/***/ }),
/* 121 */
/***/ ((module) => {

module.exports = require("nest-winston");

/***/ }),
/* 122 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WinstonConfigService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
const winston = tslib_1.__importStar(__webpack_require__(123));
__webpack_require__(124);
const path_1 = tslib_1.__importDefault(__webpack_require__(125));
let WinstonConfigService = class WinstonConfigService {
    constructor(configService) {
        this.configService = configService;
    }
    createWinstonModuleOptions() {
        const { printf, combine, timestamp, colorize } = winston.format;
        const logFormat = printf(({ timestamp, context, stack, level, message }) => {
            const stackTrace = context === 'ExceptionsHandler' ? ` (${stack})` : '';
            return `${timestamp} [${context || stack[0]}] ${level}: ${message}${stackTrace}`;
        });
        const format = combine(timestamp(), logFormat);
        const logFilePath = this.configService.get('logFilePath', { infer: true });
        const maximumFilesToKeep = this.configService.get('logFileMaximum', {
            infer: true,
        });
        const logFileDatePattern = 'YYYY-MM-DD';
        const transports = [
            new winston.transports.DailyRotateFile({
                filename: path_1.default.join(logFilePath, '%DATE%-error.log'),
                datePattern: logFileDatePattern,
                zippedArchive: false,
                maxFiles: maximumFilesToKeep,
                level: 'error',
            }),
            new winston.transports.DailyRotateFile({
                filename: path_1.default.join(logFilePath, '%DATE%-combined.log'),
                datePattern: logFileDatePattern,
                zippedArchive: false,
                maxFiles: maximumFilesToKeep,
            }),
        ];
        if (!this.configService.get('isProduction', { infer: true })) {
            const consoleFormat = combine(colorize({ all: true }), timestamp(), logFormat);
            transports.push(new winston.transports.Console({ format: consoleFormat }));
        }
        return { transports, format };
    }
};
WinstonConfigService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], WinstonConfigService);
exports.WinstonConfigService = WinstonConfigService;


/***/ }),
/* 123 */
/***/ ((module) => {

module.exports = require("winston");

/***/ }),
/* 124 */
/***/ ((module) => {

module.exports = require("winston-daily-rotate-file");

/***/ }),
/* 125 */
/***/ ((module) => {

module.exports = require("path");

/***/ }),
/* 126 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ReportsModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const timesheet_summaries_service_1 = __webpack_require__(127);
const user_schema_1 = __webpack_require__(16);
const timesheet_event_schema_1 = __webpack_require__(51);
const work_summary_schema_1 = __webpack_require__(110);
const reports_controller_1 = __webpack_require__(128);
const auth_module_1 = __webpack_require__(10);
const users_module_1 = __webpack_require__(46);
let ReportsModule = class ReportsModule {
};
ReportsModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [reports_controller_1.ReportsController],
        providers: [timesheet_summaries_service_1.TimesheetSummariesService],
        imports: [
            mongoose_1.MongooseModule.forFeature([{ name: user_schema_1.UserRecord.name, schema: user_schema_1.UserSchema }]),
            mongoose_1.MongooseModule.forFeature([
                { name: timesheet_event_schema_1.TimesheetEventRecord.name, schema: timesheet_event_schema_1.TimesheetEventSchema },
            ]),
            mongoose_1.MongooseModule.forFeature([
                { name: work_summary_schema_1.WorkSummaryRecord.name, schema: work_summary_schema_1.WorkSummarySchema },
            ]),
            auth_module_1.AuthModule,
            users_module_1.UsersModule,
        ],
    })
], ReportsModule);
exports.ReportsModule = ReportsModule;


/***/ }),
/* 127 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TimesheetSummariesService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const users_service_1 = __webpack_require__(48);
const timesheet_event_schema_1 = __webpack_require__(51);
const work_summary_schema_1 = __webpack_require__(110);
const date_utils_validator_1 = __webpack_require__(98);
let TimesheetSummariesService = class TimesheetSummariesService {
    constructor(usersService, timesheetEventModel, workSummaryModel) {
        this.usersService = usersService;
        this.timesheetEventModel = timesheetEventModel;
        this.workSummaryModel = workSummaryModel;
    }
    fillTimesheetSummariesForAllUsers(timesheetSummaries, clientId, projectId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const allUsers = yield this.usersService.findAll();
            allUsers.forEach((user) => {
                const userId = user._id.toString();
                const foundSummary = timesheetSummaries.find((timesheetSummary) => timesheetSummary.userId === userId);
                if (foundSummary) {
                    return;
                }
                if (clientId) {
                    const assignedClient = user.clients.find((client) => client._id.toString() === clientId);
                    if (!assignedClient) {
                        return;
                    }
                }
                if (projectId) {
                    const assignedProject = user.projects.find((project) => project._id.toString() === projectId);
                    if (!assignedProject) {
                        return;
                    }
                }
                const newSummary = {
                    userId,
                    userFirstName: user.firstName,
                    userLastName: user.lastName,
                    durationMinutes: 0,
                    summaryText: [],
                };
                timesheetSummaries.push(newSummary);
            });
        });
    }
    getTimesheetSummaries(startDate, endDate, clientId, projectId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            date_utils_validator_1.DateUtils.validateDateRange(startDate, endDate);
            const timesheetSummaries = [];
            const timesheetEventRecords = yield this.getTimesheetEventRecords(startDate, endDate, clientId, projectId);
            const workSummaryRecords = yield this.getWorkSummaryRecords(startDate, endDate, clientId, projectId);
            this.setSummariesForTimesheetEvents(timesheetEventRecords, timesheetSummaries);
            this.setSummariesForWorkSummaries(workSummaryRecords, timesheetSummaries);
            return timesheetSummaries;
        });
    }
    getTimesheetEventRecords(startDate, endDate, clientId, projectId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const query = {
                date: {
                    $gte: startDate,
                    $lte: endDate,
                },
            };
            if (clientId || projectId) {
                const conditions = {};
                if (clientId) {
                    conditions.client = clientId;
                }
                if (projectId) {
                    conditions.project = projectId;
                }
                query.$or = [conditions, { eventType: ['sick', 'vacation'] }];
            }
            let timesheetEventRecords = yield this.timesheetEventModel
                .find(query)
                .populate('user')
                .exec();
            timesheetEventRecords = timesheetEventRecords.filter((record) => {
                if (record.eventType === 'work') {
                    return true;
                }
                if (clientId) {
                    const assignedClient = record.user.clients.find((client) => client._id.toString() === clientId);
                    if (!assignedClient) {
                        return false;
                    }
                }
                if (projectId) {
                    const assignedProject = record.user.projects.find((project) => project._id.toString() === projectId);
                    if (!assignedProject) {
                        return false;
                    }
                }
                return true;
            });
            return timesheetEventRecords;
        });
    }
    setSummariesForTimesheetEvents(timesheetEventRecords, timesheetSummaries) {
        timesheetEventRecords.forEach((record) => {
            var _a, _b;
            const recordUserId = record.user._id.toString();
            const recordClientId = (_a = record.client) === null || _a === void 0 ? void 0 : _a._id.toString();
            const recordProjectId = (_b = record.project) === null || _b === void 0 ? void 0 : _b._id.toString();
            const foundSummary = timesheetSummaries.find((timesheetSummary) => {
                var _a, _b;
                return timesheetSummary.userId === recordUserId &&
                    timesheetSummary.eventType === record.eventType &&
                    ((_a = timesheetSummary.context) === null || _a === void 0 ? void 0 : _a.clientId) === recordClientId &&
                    ((_b = timesheetSummary.context) === null || _b === void 0 ? void 0 : _b.projectId) === recordProjectId;
            });
            if (foundSummary) {
                foundSummary.durationMinutes += record.durationMinutes;
            }
            else {
                const newSummary = {
                    userId: recordUserId,
                    userFirstName: record.user.firstName,
                    userLastName: record.user.lastName,
                    durationMinutes: record.durationMinutes,
                    eventType: record.eventType,
                    summaryText: [],
                };
                if (record.eventType === 'work') {
                    newSummary.context = {
                        clientId: recordClientId || '',
                        projectId: recordProjectId || '',
                    };
                }
                timesheetSummaries.push(newSummary);
            }
        });
    }
    getWorkSummaryRecords(startDate, endDate, clientId, projectId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const query = {
                date: {
                    $gte: startDate,
                    $lte: endDate,
                },
            };
            if (clientId) {
                query.client = clientId;
            }
            if (projectId) {
                query.project = projectId;
            }
            const workSummaryRecords = yield this.workSummaryModel
                .find(query)
                .populate('user')
                .exec();
            return workSummaryRecords;
        });
    }
    setSummariesForWorkSummaries(workSummaryRecords, timesheetSummaries) {
        workSummaryRecords.forEach((record) => {
            const recordUserId = record.user._id.toString();
            const recordClientId = record.client._id.toString();
            const recordProjectId = record.project._id.toString();
            const foundSummary = timesheetSummaries.find((timesheetSummary) => {
                var _a, _b;
                return timesheetSummary.userId === recordUserId &&
                    timesheetSummary.eventType === 'work' &&
                    ((_a = timesheetSummary.context) === null || _a === void 0 ? void 0 : _a.clientId) === recordClientId &&
                    ((_b = timesheetSummary.context) === null || _b === void 0 ? void 0 : _b.projectId) === recordProjectId;
            });
            if (foundSummary) {
                foundSummary.summaryText.push(record.summary);
            }
            else {
                const newSummary = {
                    userId: recordUserId,
                    userFirstName: record.user.firstName,
                    userLastName: record.user.lastName,
                    durationMinutes: 0,
                    eventType: 'work',
                    summaryText: [record.summary],
                    context: {
                        clientId: recordClientId || '',
                        projectId: recordProjectId || '',
                    },
                };
                timesheetSummaries.push(newSummary);
            }
        });
    }
};
TimesheetSummariesService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(1, (0, mongoose_1.InjectModel)(timesheet_event_schema_1.TimesheetEventRecord.name)),
    tslib_1.__param(2, (0, mongoose_1.InjectModel)(work_summary_schema_1.WorkSummaryRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _b : Object, typeof (_c = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _c : Object])
], TimesheetSummariesService);
exports.TimesheetSummariesService = TimesheetSummariesService;


/***/ }),
/* 128 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ReportsController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const swagger_1 = __webpack_require__(5);
const timesheet_summary_1 = __webpack_require__(129);
const get_timesheet_summaries_query_params_1 = __webpack_require__(130);
const timesheet_summaries_service_1 = __webpack_require__(127);
const auth_service_1 = __webpack_require__(13);
let ReportsController = class ReportsController {
    constructor(timesheetSummariesService, authService) {
        this.timesheetSummariesService = timesheetSummariesService;
        this.authService = authService;
    }
    getTimesheetSummaries(request, { startDate, endDate, clientId, projectId, }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            const timesheetSummaries = yield this.timesheetSummariesService.getTimesheetSummaries(startDate, endDate, clientId, projectId);
            yield this.timesheetSummariesService.fillTimesheetSummariesForAllUsers(timesheetSummaries, clientId, projectId);
            return timesheetSummaries;
        });
    }
};
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({
        description: 'Success',
        type: timesheet_summary_1.TimesheetSummary,
        isArray: true,
    }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: 'Forbidden' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Get)('timesheet-summaries'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Query)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_c = typeof Request !== "undefined" && Request) === "function" ? _c : Object, typeof (_d = typeof get_timesheet_summaries_query_params_1.GetTimesheetSummariesQueryParams !== "undefined" && get_timesheet_summaries_query_params_1.GetTimesheetSummariesQueryParams) === "function" ? _d : Object]),
    tslib_1.__metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], ReportsController.prototype, "getTimesheetSummaries", null);
ReportsController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Reports'),
    (0, common_1.Controller)('reports'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof timesheet_summaries_service_1.TimesheetSummariesService !== "undefined" && timesheet_summaries_service_1.TimesheetSummariesService) === "function" ? _a : Object, typeof (_b = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _b : Object])
], ReportsController);
exports.ReportsController = ReportsController;


/***/ }),
/* 129 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TimesheetSummary = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
class TimesheetSummary {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetSummary.prototype, "userId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetSummary.prototype, "userFirstName", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], TimesheetSummary.prototype, "userLastName", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", Number)
], TimesheetSummary.prototype, "durationMinutes", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", Array)
], TimesheetSummary.prototype, "summaryText", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.TimesheetEventType !== "undefined" && models_1.TimesheetEventType) === "function" ? _a : Object)
], TimesheetSummary.prototype, "eventType", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", Object)
], TimesheetSummary.prototype, "context", void 0);
exports.TimesheetSummary = TimesheetSummary;


/***/ }),
/* 130 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetTimesheetSummariesQueryParams = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const is_date_only_string_validator_1 = __webpack_require__(100);
const class_validator_1 = __webpack_require__(56);
class GetTimesheetSummariesQueryParams {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: new Date().toISOString().split('T')[0] }),
    (0, is_date_only_string_validator_1.IsDateOnlyString)(),
    tslib_1.__metadata("design:type", String)
], GetTimesheetSummariesQueryParams.prototype, "startDate", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: new Date().toISOString().split('T')[0] }),
    (0, is_date_only_string_validator_1.IsDateOnlyString)(),
    tslib_1.__metadata("design:type", String)
], GetTimesheetSummariesQueryParams.prototype, "endDate", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        type: String,
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", Object)
], GetTimesheetSummariesQueryParams.prototype, "clientId", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        type: String,
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", Object)
], GetTimesheetSummariesQueryParams.prototype, "projectId", void 0);
exports.GetTimesheetSummariesQueryParams = GetTimesheetSummariesQueryParams;


/***/ }),
/* 131 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.FeatureFlagsModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const feature_flag_schema_1 = __webpack_require__(132);
const feature_flags_service_1 = __webpack_require__(133);
const feature_flags_controller_1 = __webpack_require__(134);
const user_schema_1 = __webpack_require__(16);
const auth_module_1 = __webpack_require__(10);
let FeatureFlagsModule = class FeatureFlagsModule {
};
FeatureFlagsModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [feature_flags_controller_1.FeatureFlagsController],
        providers: [feature_flags_service_1.FeatureFlagsService],
        imports: [
            mongoose_1.MongooseModule.forFeature([
                { name: feature_flag_schema_1.FeatureFlagRecord.name, schema: feature_flag_schema_1.FeatureFlagSchema },
            ]),
            mongoose_1.MongooseModule.forFeature([
                {
                    name: user_schema_1.UserRecord.name,
                    schema: user_schema_1.UserSchema,
                },
            ]),
            auth_module_1.AuthModule,
        ],
    })
], FeatureFlagsModule);
exports.FeatureFlagsModule = FeatureFlagsModule;


/***/ }),
/* 132 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.FeatureFlagSchema = exports.FeatureFlagRecord = void 0;
const tslib_1 = __webpack_require__(2);
const models_1 = __webpack_require__(17);
const mongoose_1 = __webpack_require__(8);
let FeatureFlagRecord = class FeatureFlagRecord {
};
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], FeatureFlagRecord.prototype, "key", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", Boolean)
], FeatureFlagRecord.prototype, "value", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true, type: String }),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.Environment !== "undefined" && models_1.Environment) === "function" ? _a : Object)
], FeatureFlagRecord.prototype, "environment", void 0);
FeatureFlagRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'featureFlags' })
], FeatureFlagRecord);
exports.FeatureFlagRecord = FeatureFlagRecord;
const FeatureFlagSchema = mongoose_1.SchemaFactory.createForClass(FeatureFlagRecord);
exports.FeatureFlagSchema = FeatureFlagSchema;


/***/ }),
/* 133 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.FeatureFlagsService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const feature_flag_schema_1 = __webpack_require__(132);
const mongoose_2 = __webpack_require__(14);
let FeatureFlagsService = class FeatureFlagsService {
    constructor(featureFlagModel) {
        this.featureFlagModel = featureFlagModel;
    }
    getFeatureFlags(environment) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const featureFlags = yield this.featureFlagModel
                .find(environment ? { environment } : {})
                .exec();
            return featureFlags;
        });
    }
    createFeatureFlag(key, value, environment) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const trimmedKey = key.trim();
            const existingFeatureFlag = yield this.findFeatureFlagByKey(trimmedKey, environment);
            if (existingFeatureFlag) {
                throw new common_1.ConflictException(`Key '${trimmedKey}' already exists for environment '${environment}'`);
            }
            const featureFlagsModel = new this.featureFlagModel({
                key: trimmedKey,
                value,
                environment,
            });
            const featureFlagId = (_a = (yield featureFlagsModel.save())) === null || _a === void 0 ? void 0 : _a.id;
            if (!featureFlagId) {
                throw new common_1.InternalServerErrorException('Failed to save feature flag');
            }
            return featureFlagId;
        });
    }
    updateFeatureFlag(featureFlagId, value) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const featureFlag = yield this.featureFlagModel.findById(featureFlagId);
            if (!featureFlag) {
                throw new common_1.NotFoundException(`Feature flag with id '${featureFlagId}' not found`);
            }
            if (value !== undefined) {
                yield featureFlag.updateOne({ value });
            }
        });
    }
    deleteFeatureFlag(featureFlagId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const featureFlag = yield this.featureFlagModel.findById(featureFlagId);
            if (!featureFlag) {
                throw new common_1.NotFoundException(`Feature flag with id '${featureFlagId}' not found`);
            }
            yield featureFlag.deleteOne();
        });
    }
    findFeatureFlagByKey(trimmedKey, environment) {
        const featureFlagKeyRegex = '^' + trimmedKey + '$';
        return this.featureFlagModel.findOne({
            key: { $regex: featureFlagKeyRegex, $options: 'i' },
            environment,
        });
    }
};
FeatureFlagsService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(feature_flag_schema_1.FeatureFlagRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object])
], FeatureFlagsService);
exports.FeatureFlagsService = FeatureFlagsService;


/***/ }),
/* 134 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.FeatureFlagsController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const swagger_1 = __webpack_require__(5);
const feature_flag_1 = __webpack_require__(135);
const get_feature_flags_query_params_1 = __webpack_require__(136);
const feature_flags_service_1 = __webpack_require__(133);
const skip_auth_decorator_1 = __webpack_require__(38);
const create_feature_flag_dto_1 = __webpack_require__(137);
const update_feature_flag_dto_1 = __webpack_require__(138);
const update_feature_flag_params_1 = __webpack_require__(139);
const auth_service_1 = __webpack_require__(13);
const delete_feature_flag_params_1 = __webpack_require__(140);
let FeatureFlagsController = class FeatureFlagsController {
    constructor(featureFlagsService, authService) {
        this.featureFlagsService = featureFlagsService;
        this.authService = authService;
    }
    getFeatureFlags({ env: environment }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const featureFlags = yield this.featureFlagsService.getFeatureFlags(environment);
            return featureFlags.map(({ _id, key, value, environment }) => ({
                id: _id.toString(),
                key,
                value,
                environment,
            }));
        });
    }
    createFeatureFlag(request, { key, value, environment }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            const id = yield this.featureFlagsService.createFeatureFlag(key, value, environment);
            return { id };
        });
    }
    updateFeatureFlag(request, { featureFlagId }, { value }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.featureFlagsService.updateFeatureFlag(featureFlagId, value);
        });
    }
    deleteFeatureFlag(request, { featureFlagId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.featureFlagsService.deleteFeatureFlag(featureFlagId);
        });
    }
};
tslib_1.__decorate([
    (0, swagger_1.ApiOkResponse)({
        description: 'Success',
        type: feature_flag_1.FeatureFlag,
        isArray: true,
    }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, skip_auth_decorator_1.SkipAuth)(),
    (0, common_1.Get)(),
    tslib_1.__param(0, (0, common_1.Query)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_c = typeof get_feature_flags_query_params_1.GetFeatureFlagsQueryParams !== "undefined" && get_feature_flags_query_params_1.GetFeatureFlagsQueryParams) === "function" ? _c : Object]),
    tslib_1.__metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], FeatureFlagsController.prototype, "getFeatureFlags", null);
tslib_1.__decorate([
    (0, swagger_1.ApiCreatedResponse)(),
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiConflictResponse)({ description: 'Key already exists for environment' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Post)(),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object, typeof (_e = typeof create_feature_flag_dto_1.CreateFeatureFlagDto !== "undefined" && create_feature_flag_dto_1.CreateFeatureFlagDto) === "function" ? _e : Object]),
    tslib_1.__metadata("design:returntype", typeof (_f = typeof Promise !== "undefined" && Promise) === "function" ? _f : Object)
], FeatureFlagsController.prototype, "createFeatureFlag", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Feature flag id not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'featureFlagId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Patch)(':featureFlagId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object, typeof (_g = typeof update_feature_flag_params_1.UpdateFeatureFlagParams !== "undefined" && update_feature_flag_params_1.UpdateFeatureFlagParams) === "function" ? _g : Object, typeof (_h = typeof update_feature_flag_dto_1.UpdateFeatureFlagDto !== "undefined" && update_feature_flag_dto_1.UpdateFeatureFlagDto) === "function" ? _h : Object]),
    tslib_1.__metadata("design:returntype", typeof (_j = typeof Promise !== "undefined" && Promise) === "function" ? _j : Object)
], FeatureFlagsController.prototype, "updateFeatureFlag", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Feature flag id not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'featureFlagId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Delete)(':featureFlagId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object, typeof (_k = typeof delete_feature_flag_params_1.DeleteFeatureFlagParams !== "undefined" && delete_feature_flag_params_1.DeleteFeatureFlagParams) === "function" ? _k : Object]),
    tslib_1.__metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], FeatureFlagsController.prototype, "deleteFeatureFlag", null);
FeatureFlagsController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Feature flags'),
    (0, common_1.Controller)('feature-flags'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof feature_flags_service_1.FeatureFlagsService !== "undefined" && feature_flags_service_1.FeatureFlagsService) === "function" ? _a : Object, typeof (_b = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _b : Object])
], FeatureFlagsController);
exports.FeatureFlagsController = FeatureFlagsController;


/***/ }),
/* 135 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.FeatureFlag = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
class FeatureFlag {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], FeatureFlag.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], FeatureFlag.prototype, "key", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", Boolean)
], FeatureFlag.prototype, "value", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.Environment !== "undefined" && models_1.Environment) === "function" ? _a : Object)
], FeatureFlag.prototype, "environment", void 0);
exports.FeatureFlag = FeatureFlag;


/***/ }),
/* 136 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetFeatureFlagsQueryParams = void 0;
const tslib_1 = __webpack_require__(2);
const models_1 = __webpack_require__(17);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
class GetFeatureFlagsQueryParams {
}
tslib_1.__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        enum: models_1.environmentTypeList,
        example: 'dev',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsIn)(models_1.environmentTypeList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.Environment !== "undefined" && models_1.Environment) === "function" ? _a : Object)
], GetFeatureFlagsQueryParams.prototype, "env", void 0);
exports.GetFeatureFlagsQueryParams = GetFeatureFlagsQueryParams;


/***/ }),
/* 137 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateFeatureFlagDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
const models_1 = __webpack_require__(17);
const is_not_blank_string_validator_1 = __webpack_require__(58);
class CreateFeatureFlagDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'myFeatureFlag' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateFeatureFlagDto.prototype, "key", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: true }),
    (0, class_validator_1.IsBoolean)(),
    tslib_1.__metadata("design:type", Boolean)
], CreateFeatureFlagDto.prototype, "value", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.environmentTypeList,
        example: 'dev',
    }),
    (0, class_validator_1.IsIn)(models_1.environmentTypeList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.Environment !== "undefined" && models_1.Environment) === "function" ? _a : Object)
], CreateFeatureFlagDto.prototype, "environment", void 0);
exports.CreateFeatureFlagDto = CreateFeatureFlagDto;


/***/ }),
/* 138 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateFeatureFlagDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(56);
class UpdateFeatureFlagDto {
}
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: true }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsBoolean)(),
    tslib_1.__metadata("design:type", Boolean)
], UpdateFeatureFlagDto.prototype, "value", void 0);
exports.UpdateFeatureFlagDto = UpdateFeatureFlagDto;


/***/ }),
/* 139 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateFeatureFlagParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class UpdateFeatureFlagParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], UpdateFeatureFlagParams.prototype, "featureFlagId", void 0);
exports.UpdateFeatureFlagParams = UpdateFeatureFlagParams;


/***/ }),
/* 140 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DeleteFeatureFlagParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(56);
class DeleteFeatureFlagParams {
}
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], DeleteFeatureFlagParams.prototype, "featureFlagId", void 0);
exports.DeleteFeatureFlagParams = DeleteFeatureFlagParams;


/***/ }),
/* 141 */
/***/ ((module) => {

module.exports = require("fs");

/***/ }),
/* 142 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getBooleanEnvironmentVariable = exports.getStringEnvironmentVariable = exports.getIntegerEnvironmentVariable = void 0;
const getIntegerEnvironmentVariable = (variableKey, defaultValue) => {
    const variable = process.env[variableKey];
    return (variable && parseInt(variable)) || defaultValue;
};
exports.getIntegerEnvironmentVariable = getIntegerEnvironmentVariable;
const getStringEnvironmentVariable = (variableKey, defaultValue = '') => {
    const variable = process.env[variableKey];
    return variable !== null && variable !== void 0 ? variable : defaultValue;
};
exports.getStringEnvironmentVariable = getStringEnvironmentVariable;
const getBooleanEnvironmentVariable = (variableKey, defaultValue = false) => {
    const variable = process.env[variableKey];
    return variable === 'true' || defaultValue;
};
exports.getBooleanEnvironmentVariable = getBooleanEnvironmentVariable;


/***/ })
/******/ 	]);
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;

// Copyright 2023 Orbital Technologies, Inc.
Object.defineProperty(exports, "__esModule", ({ value: true }));
const bootstrap_1 = __webpack_require__(1);
(0, bootstrap_1.bootstrap)();

})();

var __webpack_export_target__ = exports;
for(var i in __webpack_exports__) __webpack_export_target__[i] = __webpack_exports__[i];
if(__webpack_exports__.__esModule) Object.defineProperty(__webpack_export_target__, "__esModule", { value: true });
/******/ })()
;
//# sourceMappingURL=main.js.map