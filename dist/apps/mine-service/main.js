/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ([
/* 0 */,
/* 1 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.bootstrap = void 0;
const tslib_1 = __webpack_require__(2);
const cookie_parser_1 = tslib_1.__importDefault(__webpack_require__(3));
const core_1 = __webpack_require__(4);
const swagger_1 = __webpack_require__(5);
const app_module_1 = __webpack_require__(6);
const common_1 = __webpack_require__(7);
const nest_winston_1 = __webpack_require__(55);
const fs_1 = __webpack_require__(69);
const assert_is_truthy_1 = __webpack_require__(29);
const env_helper_1 = __webpack_require__(70);
function bootstrap() {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const app = yield createApp();
        app.useLogger(app.get(nest_winston_1.WINSTON_MODULE_NEST_PROVIDER));
        const config = new swagger_1.DocumentBuilder()
            .setTitle('MINE -- API Documentation')
            .setDescription('API documentation for MINE')
            .setVersion('1.0')
            .addTag('mine')
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


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const config_1 = __webpack_require__(9);
const auth_module_1 = __webpack_require__(10);
const users_module_1 = __webpack_require__(35);
const health_module_1 = __webpack_require__(46);
const load_config_1 = __webpack_require__(49);
const mongoose_config_service_1 = __webpack_require__(50);
const user_module_1 = __webpack_require__(51);
const logger_middleware_1 = __webpack_require__(54);
const nest_winston_1 = __webpack_require__(55);
const winston_config_service_1 = __webpack_require__(56);
const mining_hardwares_module_1 = __webpack_require__(60);
let AppModule = class AppModule {
    configure(consumer) {
        consumer.apply(logger_middleware_1.LoggerMiddleware).forRoutes('*');
    }
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = tslib_1.__decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({ isGlobal: true, load: [load_config_1.loadConfig], cache: true }),
            nest_winston_1.WinstonModule.forRootAsync({ useClass: winston_config_service_1.WinstonConfigService }),
            mongoose_1.MongooseModule.forRootAsync({
                useClass: mongoose_config_service_1.MongooseConfigService,
            }),
            auth_module_1.AuthModule,
            health_module_1.HealthModule,
            user_module_1.UserModule,
            users_module_1.UsersModule,
            mining_hardwares_module_1.MiningHardwaresModule,
        ],
    })
], AppModule);


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


// Copyright 2024 applibrium.com
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
const auth_controller_1 = __webpack_require__(24);
const auth_guard_1 = __webpack_require__(30);
const jwt_config_helper_1 = __webpack_require__(34);
const user_schema_1 = __webpack_require__(16);
let AuthModule = class AuthModule {
};
exports.AuthModule = AuthModule;
exports.AuthModule = AuthModule = tslib_1.__decorate([
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


/***/ }),
/* 11 */
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),
/* 12 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AccessTokenSchema = exports.AccessTokenRecord = void 0;
const tslib_1 = __webpack_require__(2);
const mongoose_1 = __webpack_require__(8);
const swagger_1 = __webpack_require__(5);
let AccessTokenRecord = class AccessTokenRecord {
};
exports.AccessTokenRecord = AccessTokenRecord;
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
exports.AccessTokenRecord = AccessTokenRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'accessTokens' })
], AccessTokenRecord);
const AccessTokenSchema = mongoose_1.SchemaFactory.createForClass(AccessTokenRecord);
exports.AccessTokenSchema = AccessTokenSchema;


/***/ }),
/* 13 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
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
const api_helper_1 = __webpack_require__(20);
const assert_user_exists_1 = __webpack_require__(21);
const assert_user_role_is_admin_1 = __webpack_require__(23);
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
exports.AuthService = AuthService;
exports.AuthService = AuthService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(2, (0, mongoose_1.InjectModel)(access_token_schema_1.AccessTokenRecord.name)),
    tslib_1.__param(3, (0, mongoose_1.InjectModel)(user_schema_1.UserRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object, typeof (_c = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _c : Object, typeof (_d = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _d : Object])
], AuthService);


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


// Copyright 2024 applibrium.com
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserSchema = exports.UserRecord = void 0;
const tslib_1 = __webpack_require__(2);
const mongoose_1 = __webpack_require__(8);
const bcrypt = tslib_1.__importStar(__webpack_require__(15));
const models_1 = __webpack_require__(17);
let UserRecord = class UserRecord {
};
exports.UserRecord = UserRecord;
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
exports.UserRecord = UserRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'users' })
], UserRecord);
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


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(2);
tslib_1.__exportStar(__webpack_require__(18), exports);
tslib_1.__exportStar(__webpack_require__(19), exports);


/***/ }),
/* 18 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.User = exports.AssignedActivity = exports.AssignedProject = exports.AssignedClient = exports.userStatusList = exports.userRoleList = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
exports.userRoleList = ['admin', 'member'];
exports.userStatusList = ['enabled', 'disabled'];
// TODO: Define interface here and remove NestJs decorators (shouldn't be
// in code used directly in UI)
class AssignedClient {
}
exports.AssignedClient = AssignedClient;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedClient.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedClient.prototype, "name", void 0);
class AssignedProject {
}
exports.AssignedProject = AssignedProject;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedProject.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedProject.prototype, "name", void 0);
class AssignedActivity {
}
exports.AssignedActivity = AssignedActivity;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedActivity.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AssignedActivity.prototype, "name", void 0);
class User {
}
exports.User = User;
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


/***/ }),
/* 19 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 20 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getCurrentUserId = void 0;
const getCurrentUserId = (request) => {
    const decodedToken = request['user'];
    return decodedToken.sub;
};
exports.getCurrentUserId = getCurrentUserId;


/***/ }),
/* 21 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.assertUserExists = void 0;
const assert_is_defined_1 = __webpack_require__(22);
function assertUserExists(user, userId) {
    (0, assert_is_defined_1.assertIsDefined)(user, `User for id ${userId} not found`);
}
exports.assertUserExists = assertUserExists;


/***/ }),
/* 22 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
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
/* 23 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
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
/* 24 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
const swagger_1 = __webpack_require__(5);
const express_1 = __webpack_require__(25);
const auth_service_1 = __webpack_require__(13);
const auth_dto_1 = __webpack_require__(26);
const skip_auth_decorator_1 = __webpack_require__(27);
const auth_helper_1 = __webpack_require__(28);
const assert_is_truthy_1 = __webpack_require__(29);
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
exports.AuthController = AuthController;
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
exports.AuthController = AuthController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Authentication'),
    (0, common_1.Controller)('auth'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object])
], AuthController);


/***/ }),
/* 25 */
/***/ ((module) => {

module.exports = require("express");

/***/ }),
/* 26 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AccessTokenDto = exports.SignInDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
class SignInDto {
}
exports.SignInDto = SignInDto;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], SignInDto.prototype, "email", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], SignInDto.prototype, "password", void 0);
class AccessTokenDto {
}
exports.AccessTokenDto = AccessTokenDto;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], AccessTokenDto.prototype, "accessToken", void 0);


/***/ }),
/* 27 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SkipAuth = exports.SKIP_AUTH_KEY = void 0;
const common_1 = __webpack_require__(7);
exports.SKIP_AUTH_KEY = 'skipAuth';
const SkipAuth = () => (0, common_1.SetMetadata)(exports.SKIP_AUTH_KEY, true);
exports.SkipAuth = SkipAuth;


/***/ }),
/* 28 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2024 applibrium.com
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
/* 29 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
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
/* 30 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthGuard = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
const core_1 = __webpack_require__(4);
const jwt_1 = __webpack_require__(11);
const datetime_1 = __webpack_require__(31);
const skip_auth_decorator_1 = __webpack_require__(27);
const auth_helper_1 = __webpack_require__(28);
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
exports.AuthGuard = AuthGuard;
exports.AuthGuard = AuthGuard = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object, typeof (_c = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _c : Object, typeof (_d = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _d : Object])
], AuthGuard);


/***/ }),
/* 31 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(2);
tslib_1.__exportStar(__webpack_require__(32), exports);


/***/ }),
/* 32 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.dateToISODateString = exports.isoDateStringToLocalDate = exports.formatMinutesAsTime = exports.formatEventTime = exports.roundEventTime = exports.parseEventTimeString = exports.convertTimeInputString = exports.timeInputRegex = exports.convertHoursToMinutes = exports.convertMinutesToHours = exports.getDateForWeekday = exports.getNewDate = exports.weekdayStrings = void 0;
const tslib_1 = __webpack_require__(2);
const dayjs_1 = tslib_1.__importDefault(__webpack_require__(33));
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
/* 33 */
/***/ ((module) => {

module.exports = require("dayjs");

/***/ }),
/* 34 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2024 applibrium.com
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
/* 35 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const user_schema_1 = __webpack_require__(16);
const users_controller_1 = __webpack_require__(36);
const users_service_1 = __webpack_require__(37);
const users_assembler_1 = __webpack_require__(39);
const auth_module_1 = __webpack_require__(10);
let UsersModule = class UsersModule {
};
exports.UsersModule = UsersModule;
exports.UsersModule = UsersModule = tslib_1.__decorate([
    (0, common_1.Module)({
        exports: [users_service_1.UsersService],
        controllers: [users_controller_1.UsersController],
        providers: [users_service_1.UsersService, users_assembler_1.UsersAssembler],
        imports: [
            mongoose_1.MongooseModule.forFeature([{ name: user_schema_1.UserRecord.name, schema: user_schema_1.UserSchema }]),
            auth_module_1.AuthModule,
        ],
    })
], UsersModule);


/***/ }),
/* 36 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t, _u;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const users_service_1 = __webpack_require__(37);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
const users_assembler_1 = __webpack_require__(39);
const get_user_params_1 = __webpack_require__(40);
const create_user_dto_1 = __webpack_require__(42);
const update_user_status_dto_1 = __webpack_require__(44);
const update_user_password_dto_1 = __webpack_require__(45);
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
};
exports.UsersController = UsersController;
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
exports.UsersController = UsersController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Users (Admin)'),
    (0, common_1.Controller)('users'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof users_assembler_1.UsersAssembler !== "undefined" && users_assembler_1.UsersAssembler) === "function" ? _b : Object, typeof (_c = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _c : Object])
], UsersController);


/***/ }),
/* 37 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const mongoose_2 = __webpack_require__(14);
const user_schema_1 = __webpack_require__(16);
const bcrypt = tslib_1.__importStar(__webpack_require__(15));
const assert_user_exists_1 = __webpack_require__(21);
const user_not_found_exception_1 = __webpack_require__(38);
let UsersService = class UsersService {
    constructor(userModel) {
        this.userModel = userModel;
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
            return (_a = (yield find.exec())) !== null && _a !== void 0 ? _a : undefined;
        });
    }
    findEnabledUserByEmail(email) {
        return this.userModel.findOne({
            email: email.toLowerCase(),
            status: 'enabled',
        });
    }
};
exports.UsersService = UsersService;
exports.UsersService = UsersService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(user_schema_1.UserRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object])
], UsersService);


/***/ }),
/* 38 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
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
/* 39 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersAssembler = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
let UsersAssembler = class UsersAssembler {
    assembleUser(userRecord) {
        return {
            id: userRecord._id.toString(),
            firstName: userRecord.firstName,
            lastName: userRecord.lastName,
            email: userRecord.email,
            role: userRecord.role,
            status: userRecord.status,
        };
    }
};
exports.UsersAssembler = UsersAssembler;
exports.UsersAssembler = UsersAssembler = tslib_1.__decorate([
    (0, common_1.Injectable)()
], UsersAssembler);


/***/ }),
/* 40 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GetUserParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(41);
class GetUserParams {
}
exports.GetUserParams = GetUserParams;
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], GetUserParams.prototype, "userId", void 0);


/***/ }),
/* 41 */
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),
/* 42 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateUserDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(41);
const models_1 = __webpack_require__(17);
const is_not_blank_string_validator_1 = __webpack_require__(43);
class CreateUserDto {
}
exports.CreateUserDto = CreateUserDto;
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


/***/ }),
/* 43 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IsNotBlankString = exports.IsNotBlankStringValidator = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(41);
let IsNotBlankStringValidator = class IsNotBlankStringValidator {
    validate(value) {
        return !!(value === null || value === void 0 ? void 0 : value.trim());
    }
    defaultMessage({ property }) {
        return `${property} must not be an empty string or only white spaces`;
    }
};
exports.IsNotBlankStringValidator = IsNotBlankStringValidator;
exports.IsNotBlankStringValidator = IsNotBlankStringValidator = tslib_1.__decorate([
    (0, class_validator_1.ValidatorConstraint)({ name: 'isNotBlankString', async: false })
], IsNotBlankStringValidator);
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
/* 44 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateUserStatusDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(41);
const models_1 = __webpack_require__(17);
class UpdateUserStatusDto {
}
exports.UpdateUserStatusDto = UpdateUserStatusDto;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({
        enum: models_1.userStatusList,
        example: 'enabled',
    }),
    (0, class_validator_1.IsIn)(models_1.userStatusList),
    tslib_1.__metadata("design:type", typeof (_a = typeof models_1.UserStatus !== "undefined" && models_1.UserStatus) === "function" ? _a : Object)
], UpdateUserStatusDto.prototype, "status", void 0);


/***/ }),
/* 45 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateUserPasswordDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const is_not_blank_string_validator_1 = __webpack_require__(43);
class UpdateUserPasswordDto {
}
exports.UpdateUserPasswordDto = UpdateUserPasswordDto;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], UpdateUserPasswordDto.prototype, "password", void 0);


/***/ }),
/* 46 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HealthModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const health_controller_1 = __webpack_require__(47);
const health_service_1 = __webpack_require__(48);
let HealthModule = class HealthModule {
};
exports.HealthModule = HealthModule;
exports.HealthModule = HealthModule = tslib_1.__decorate([
    (0, common_1.Module)({
        imports: [],
        controllers: [health_controller_1.HealthController],
        providers: [health_service_1.HealthService],
    })
], HealthModule);


/***/ }),
/* 47 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HealthController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const health_service_1 = __webpack_require__(48);
const swagger_1 = __webpack_require__(5);
const skip_auth_decorator_1 = __webpack_require__(27);
let HealthController = class HealthController {
    constructor(healthService) {
        this.healthService = healthService;
    }
    getHello() {
        return this.healthService.getHello();
    }
};
exports.HealthController = HealthController;
tslib_1.__decorate([
    (0, skip_auth_decorator_1.SkipAuth)(),
    (0, common_1.Get)('hello'),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", []),
    tslib_1.__metadata("design:returntype", Object)
], HealthController.prototype, "getHello", null);
exports.HealthController = HealthController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Health'),
    (0, common_1.Controller)('health'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof health_service_1.HealthService !== "undefined" && health_service_1.HealthService) === "function" ? _a : Object])
], HealthController);


/***/ }),
/* 48 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
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
            name: 'MINE API service',
            isProduction: this.configService.get('isProduction'),
        };
    }
};
exports.HealthService = HealthService;
exports.HealthService = HealthService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], HealthService);


/***/ }),
/* 49 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.loadConfig = void 0;
const loadConfig = () => {
    const config = {
        databaseUri: process.env.DATABASE_URI || 'mongodb://127.0.0.1:27017/mine',
        isProduction: process.env.NODE_ENV === 'production',
        logFileMaximum: process.env.LOG_FILE_MAXIMUM || '30d',
        logFilePath: process.env.LOG_FILE_PATH || './logs',
        jwtAccessExpiresInMinutes: process.env.JWT_ACCESS_EXPIRES_IN_MINUTES || '60',
        jwtAccessSecret: process.env.JWT_ACCESS_SECRET || 'secret_access',
        jwtRefreshExpiresInMinutes: process.env.JWT_REFRESH_EXPIRES_IN_MINUTES || '1440',
        jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'secret_refresh',
        useHttps: process.env.USE_HTTPS === 'true',
    };
    return config;
};
exports.loadConfig = loadConfig;


/***/ }),
/* 50 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
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
exports.MongooseConfigService = MongooseConfigService;
exports.MongooseConfigService = MongooseConfigService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], MongooseConfigService);


/***/ }),
/* 51 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const user_controller_1 = __webpack_require__(52);
const users_service_1 = __webpack_require__(37);
const users_assembler_1 = __webpack_require__(39);
const user_schema_1 = __webpack_require__(16);
let UserModule = class UserModule {
};
exports.UserModule = UserModule;
exports.UserModule = UserModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [user_controller_1.UserController],
        providers: [users_service_1.UsersService, users_assembler_1.UsersAssembler],
        imports: [
            mongoose_1.MongooseModule.forFeature([{ name: user_schema_1.UserRecord.name, schema: user_schema_1.UserSchema }]),
        ],
    })
], UserModule);


/***/ }),
/* 52 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a, _b, _c, _d, _e, _f, _g;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const swagger_1 = __webpack_require__(5);
const models_1 = __webpack_require__(17);
const express_1 = __webpack_require__(25);
const api_helper_1 = __webpack_require__(20);
const users_assembler_1 = __webpack_require__(39);
const users_service_1 = __webpack_require__(37);
const assert_user_exists_1 = __webpack_require__(21);
const change_password_dto_1 = __webpack_require__(53);
let UserController = class UserController {
    constructor(usersService, usersAssembler) {
        this.usersService = usersService;
        this.usersAssembler = usersAssembler;
    }
    getUserInformation(request) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            const userRecord = yield this.usersService.findById(userId);
            (0, assert_user_exists_1.assertUserExists)(userRecord, userId);
            return this.usersAssembler.assembleUser(userRecord);
        });
    }
    changePassword(request, { currentPassword, newPassword }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const userId = (0, api_helper_1.getCurrentUserId)(request);
            yield this.usersService.changeUserPassword(userId, currentPassword, newPassword);
        });
    }
};
exports.UserController = UserController;
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOkResponse)({ description: 'Success', type: models_1.User }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Get)(),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_c = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _c : Object]),
    tslib_1.__metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], UserController.prototype, "getUserInformation", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, common_1.Put)('password'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_e = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _e : Object, typeof (_f = typeof change_password_dto_1.ChangePasswordDto !== "undefined" && change_password_dto_1.ChangePasswordDto) === "function" ? _f : Object]),
    tslib_1.__metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], UserController.prototype, "changePassword", null);
exports.UserController = UserController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('Current user'),
    (0, common_1.Controller)('user'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof users_assembler_1.UsersAssembler !== "undefined" && users_assembler_1.UsersAssembler) === "function" ? _b : Object])
], UserController);


/***/ }),
/* 53 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ChangePasswordDto = void 0;
const tslib_1 = __webpack_require__(2);
const is_not_blank_string_validator_1 = __webpack_require__(43);
const swagger_1 = __webpack_require__(5);
class ChangePasswordDto {
}
exports.ChangePasswordDto = ChangePasswordDto;
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


/***/ }),
/* 54 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoggerMiddleware = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const nest_winston_1 = __webpack_require__(55);
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
exports.LoggerMiddleware = LoggerMiddleware;
exports.LoggerMiddleware = LoggerMiddleware = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, common_1.Inject)(nest_winston_1.WINSTON_MODULE_NEST_PROVIDER)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof common_1.LoggerService !== "undefined" && common_1.LoggerService) === "function" ? _a : Object])
], LoggerMiddleware);


/***/ }),
/* 55 */
/***/ ((module) => {

module.exports = require("nest-winston");

/***/ }),
/* 56 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WinstonConfigService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(9);
const winston = tslib_1.__importStar(__webpack_require__(57));
__webpack_require__(58);
const path_1 = tslib_1.__importDefault(__webpack_require__(59));
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
exports.WinstonConfigService = WinstonConfigService;
exports.WinstonConfigService = WinstonConfigService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], WinstonConfigService);


/***/ }),
/* 57 */
/***/ ((module) => {

module.exports = require("winston");

/***/ }),
/* 58 */
/***/ ((module) => {

module.exports = require("winston-daily-rotate-file");

/***/ }),
/* 59 */
/***/ ((module) => {

module.exports = require("path");

/***/ }),
/* 60 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MiningHardwaresModule = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const mining_hardware_schema_1 = __webpack_require__(61);
const mining_hardwares_service_1 = __webpack_require__(62);
const mining_hardwares_controller_1 = __webpack_require__(63);
const user_schema_1 = __webpack_require__(16);
const auth_module_1 = __webpack_require__(10);
let MiningHardwaresModule = class MiningHardwaresModule {
};
exports.MiningHardwaresModule = MiningHardwaresModule;
exports.MiningHardwaresModule = MiningHardwaresModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [mining_hardwares_controller_1.MiningHardwaresController],
        providers: [mining_hardwares_service_1.MiningHardwaresService],
        imports: [
            mongoose_1.MongooseModule.forFeature([
                { name: mining_hardware_schema_1.MiningHardwareRecord.name, schema: mining_hardware_schema_1.MiningHardwareSchema },
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
], MiningHardwaresModule);


/***/ }),
/* 61 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MiningHardwareSchema = exports.MiningHardwareRecord = void 0;
const tslib_1 = __webpack_require__(2);
/* import { Environment } from '@mine/shared/models'; */
const mongoose_1 = __webpack_require__(8);
let MiningHardwareRecord = class MiningHardwareRecord {
};
exports.MiningHardwareRecord = MiningHardwareRecord;
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], MiningHardwareRecord.prototype, "name", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], MiningHardwareRecord.prototype, "location", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], MiningHardwareRecord.prototype, "hashRate", void 0);
exports.MiningHardwareRecord = MiningHardwareRecord = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ collection: 'miningHardwares' })
], MiningHardwareRecord);
const MiningHardwareSchema = mongoose_1.SchemaFactory.createForClass(MiningHardwareRecord);
exports.MiningHardwareSchema = MiningHardwareSchema;


/***/ }),
/* 62 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MiningHardwaresService = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(8);
const mining_hardware_schema_1 = __webpack_require__(61);
const mongoose_2 = __webpack_require__(14);
let MiningHardwaresService = class MiningHardwaresService {
    constructor(miningHardwareModel) {
        this.miningHardwareModel = miningHardwareModel;
    }
    getMiningHardwares() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const miningHardwares = yield this.miningHardwareModel.find().exec();
            return miningHardwares;
        });
    }
    createMiningHardware(name, location, hashRate) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const trimmedKey = name.trim();
            const existingMiningHardware = yield this.findMiningHardwareByName(trimmedKey);
            if (existingMiningHardware) {
                throw new common_1.ConflictException(`Key '${trimmedKey}' already exists`);
            }
            const miningHardwareModel = new this.miningHardwareModel({
                name: trimmedKey,
                location,
                hashRate,
            });
            const miningHardwareId = (_a = (yield miningHardwareModel.save())) === null || _a === void 0 ? void 0 : _a.id;
            if (!miningHardwareId) {
                throw new common_1.InternalServerErrorException('Failed to save mining hardware');
            }
            return miningHardwareId;
        });
    }
    updateMiningHardware(miningHardwareId, name, location, hashRate) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const miningHardware = yield this.miningHardwareModel.findById(miningHardwareId);
            if (!miningHardware) {
                throw new common_1.NotFoundException(`Mining  hardware with id '${miningHardwareId}' not found`);
            }
            yield miningHardware.updateOne({ name, location, hashRate });
        });
    }
    deleteMiningHardware(miningHardwareId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const miningHardware = yield this.miningHardwareModel.findById(miningHardwareId);
            if (!miningHardware) {
                throw new common_1.NotFoundException(`Mining  hardware with id '${miningHardwareId}' not found`);
            }
            yield miningHardware.deleteOne();
        });
    }
    findMiningHardwareByName(trimmedKey) {
        const miningHardwareKeyRegex = '^' + trimmedKey + '$';
        return this.miningHardwareModel.findOne({
            key: { $regex: miningHardwareKeyRegex, $options: 'i' },
        });
    }
};
exports.MiningHardwaresService = MiningHardwaresService;
exports.MiningHardwaresService = MiningHardwaresService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(mining_hardware_schema_1.MiningHardwareRecord.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object])
], MiningHardwaresService);


/***/ }),
/* 63 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MiningHardwaresController = void 0;
const tslib_1 = __webpack_require__(2);
const common_1 = __webpack_require__(7);
const swagger_1 = __webpack_require__(5);
const mining_hardware_1 = __webpack_require__(64);
const mining_hardwares_service_1 = __webpack_require__(62);
const skip_auth_decorator_1 = __webpack_require__(27);
const create_mining_hardware_dto_1 = __webpack_require__(65);
const update_mining_hardware_dto_1 = __webpack_require__(66);
const update_mining_hardware_params_1 = __webpack_require__(67);
const auth_service_1 = __webpack_require__(13);
const delete_mining_hardware_params_1 = __webpack_require__(68);
let MiningHardwaresController = class MiningHardwaresController {
    constructor(miningHardwaresService, authService) {
        this.miningHardwaresService = miningHardwaresService;
        this.authService = authService;
    }
    getMiningHardwares() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const miningHardwares = yield this.miningHardwaresService.getMiningHardwares();
            return miningHardwares.map(({ _id, name, location, hashRate }) => ({
                id: _id.toString(),
                name,
                location,
                hashRate,
            }));
        });
    }
    createMiningHardware(request, { name, location, hashRate }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            const id = yield this.miningHardwaresService.createMiningHardware(name, location, hashRate);
            return { id };
        });
    }
    updateMiningHardware(request, { miningHardwareId }, { name, location, hashRate }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!miningHardwareId || !name || !location || !hashRate) {
                throw new common_1.BadRequestException('All parameters must be provided');
            }
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.miningHardwaresService.updateMiningHardware(miningHardwareId, name, location, hashRate);
        });
    }
    deleteMiningHardware(request, { miningHardwareId }) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            yield this.authService.ensureCurrentUserIsAdmin(request);
            yield this.miningHardwaresService.deleteMiningHardware(miningHardwareId);
        });
    }
};
exports.MiningHardwaresController = MiningHardwaresController;
tslib_1.__decorate([
    (0, swagger_1.ApiOkResponse)({
        description: 'Success',
        type: mining_hardware_1.MiningHardware,
        isArray: true,
    }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, skip_auth_decorator_1.SkipAuth)(),
    (0, common_1.Get)(),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", []),
    tslib_1.__metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], MiningHardwaresController.prototype, "getMiningHardwares", null);
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
    tslib_1.__metadata("design:paramtypes", [Object, typeof (_d = typeof create_mining_hardware_dto_1.CreateMiningHardwareDto !== "undefined" && create_mining_hardware_dto_1.CreateMiningHardwareDto) === "function" ? _d : Object]),
    tslib_1.__metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], MiningHardwaresController.prototype, "createMiningHardware", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Mining  hardware id not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'miningHardwareId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Patch)(':miningHardwareId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object, typeof (_f = typeof update_mining_hardware_params_1.UpdateMiningHardwareParams !== "undefined" && update_mining_hardware_params_1.UpdateMiningHardwareParams) === "function" ? _f : Object, typeof (_g = typeof update_mining_hardware_dto_1.UpdateMiningHardwareDto !== "undefined" && update_mining_hardware_dto_1.UpdateMiningHardwareDto) === "function" ? _g : Object]),
    tslib_1.__metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
], MiningHardwaresController.prototype, "updateMiningHardware", null);
tslib_1.__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiNoContentResponse)({ description: 'No content' }),
    (0, swagger_1.ApiBadRequestResponse)({ description: 'Bad request' }),
    (0, swagger_1.ApiUnauthorizedResponse)({ description: 'Unauthorized' }),
    (0, swagger_1.ApiForbiddenResponse)({ description: "User's role is not 'admin'" }),
    (0, swagger_1.ApiNotFoundResponse)({ description: 'Mining  hardware id not found' }),
    (0, swagger_1.ApiInternalServerErrorResponse)({ description: 'Internal error' }),
    (0, swagger_1.ApiParam)({ required: true, name: 'miningHardwareId' }),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.Delete)(':miningHardwareId'),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Param)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object, typeof (_j = typeof delete_mining_hardware_params_1.DeleteMiningHardwareParams !== "undefined" && delete_mining_hardware_params_1.DeleteMiningHardwareParams) === "function" ? _j : Object]),
    tslib_1.__metadata("design:returntype", typeof (_k = typeof Promise !== "undefined" && Promise) === "function" ? _k : Object)
], MiningHardwaresController.prototype, "deleteMiningHardware", null);
exports.MiningHardwaresController = MiningHardwaresController = tslib_1.__decorate([
    (0, swagger_1.ApiTags)('mining  hardwares'),
    (0, common_1.Controller)('mining-hardwares'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mining_hardwares_service_1.MiningHardwaresService !== "undefined" && mining_hardwares_service_1.MiningHardwaresService) === "function" ? _a : Object, typeof (_b = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _b : Object])
], MiningHardwaresController);


/***/ }),
/* 64 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MiningHardware = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
class MiningHardware {
}
exports.MiningHardware = MiningHardware;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], MiningHardware.prototype, "id", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], MiningHardware.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], MiningHardware.prototype, "location", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)(),
    tslib_1.__metadata("design:type", String)
], MiningHardware.prototype, "hashRate", void 0);


/***/ }),
/* 65 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateMiningHardwareDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const is_not_blank_string_validator_1 = __webpack_require__(43);
class CreateMiningHardwareDto {
}
exports.CreateMiningHardwareDto = CreateMiningHardwareDto;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'name' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateMiningHardwareDto.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'location' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateMiningHardwareDto.prototype, "location", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'hashRate' }),
    (0, is_not_blank_string_validator_1.IsNotBlankString)(),
    tslib_1.__metadata("design:type", String)
], CreateMiningHardwareDto.prototype, "hashRate", void 0);


/***/ }),
/* 66 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateMiningHardwareDto = void 0;
const tslib_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(5);
const class_validator_1 = __webpack_require__(41);
class UpdateMiningHardwareDto {
}
exports.UpdateMiningHardwareDto = UpdateMiningHardwareDto;
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'true' }),
    (0, class_validator_1.IsOptional)(),
    tslib_1.__metadata("design:type", String)
], UpdateMiningHardwareDto.prototype, "name", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'true' }),
    (0, class_validator_1.IsOptional)(),
    tslib_1.__metadata("design:type", String)
], UpdateMiningHardwareDto.prototype, "location", void 0);
tslib_1.__decorate([
    (0, swagger_1.ApiProperty)({ example: 'true' }),
    (0, class_validator_1.IsOptional)(),
    tslib_1.__metadata("design:type", String)
], UpdateMiningHardwareDto.prototype, "hashRate", void 0);


/***/ }),
/* 67 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateMiningHardwareParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(41);
class UpdateMiningHardwareParams {
}
exports.UpdateMiningHardwareParams = UpdateMiningHardwareParams;
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", Object)
], UpdateMiningHardwareParams.prototype, "miningHardwareId", void 0);


/***/ }),
/* 68 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DeleteMiningHardwareParams = void 0;
const tslib_1 = __webpack_require__(2);
const class_validator_1 = __webpack_require__(41);
class DeleteMiningHardwareParams {
}
exports.DeleteMiningHardwareParams = DeleteMiningHardwareParams;
tslib_1.__decorate([
    (0, class_validator_1.IsMongoId)(),
    tslib_1.__metadata("design:type", String)
], DeleteMiningHardwareParams.prototype, "miningHardwareId", void 0);


/***/ }),
/* 69 */
/***/ ((module) => {

module.exports = require("fs");

/***/ }),
/* 70 */
/***/ ((__unused_webpack_module, exports) => {


// Copyright 2024 applibrium.com
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

// Copyright 2024 applibrium.com
Object.defineProperty(exports, "__esModule", ({ value: true }));
const bootstrap_1 = __webpack_require__(1);
(0, bootstrap_1.bootstrap)();

})();

var __webpack_export_target__ = exports;
for(var i in __webpack_exports__) __webpack_export_target__[i] = __webpack_exports__[i];
if(__webpack_exports__.__esModule) Object.defineProperty(__webpack_export_target__, "__esModule", { value: true });
/******/ })()
;