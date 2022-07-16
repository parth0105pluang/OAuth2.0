import * as express from 'express';
export const appsRouter = express.Router();
import * as AppsController from '../controllers/apps.controller';
import * as UserController from '../controllers/user.controller';
appsRouter.post('/register/app', AppsController.registerApp);
appsRouter.get('/token/:appName/:LoginMethod', UserController.logInMiddwre, AppsController.reqToken);
appsRouter.post('/validate/:AppKey/:token', AppsController.ValidateAppKey, AppsController.validateToken);
