import { initializeParams } from './helpers/init';
import { VLOverWSHandler } from './types/v';
import { TROverWSHandler } from './types/t';
import { fallback, serveIcon, renderError, renderSecrets, handlePanel, handleSubscriptions, handleLogin, handleError } from './helpers/helpers';
import { logout } from './idetify/auth';

export default {
	async fetch(request, env) {
		try {
			initializeParams(request, env);
			const upgradeHeader = request.headers.get('Upgrade');
			const path = globalThis.pathName;
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				if (path.startsWith('/app')) return await handlePanel(request, env);
				if (path.startsWith('/link')) return await handleSubscriptions(request, env);
				if (path.startsWith('/sign')) return await handleLogin(request, env);
				if (path.startsWith('/exit')) return await logout(request, env);
				if (path.startsWith('/problem')) return await renderError();
				if (path.startsWith('/encrypted')) return await renderSecrets();
				if (path.startsWith('/file.ico')) return await serveIcon();
				return await fallback(request);
			} else {
				return path.startsWith('/api')
					? await TROverWSHandler(request)
					: await VLOverWSHandler(request);
			}
		} catch (error) {
			return await handleError(error);
		}
	}
}