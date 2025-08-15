import { initializeParams } from './helpers/init';
import { baydc } from './types/v';
import { pyenv } from './types/t';
import { ydmzk, bkcez, mfdkx, slymt, handlePanel, handleSubscriptions, handleLogin, handleError } from './helpers/helpers';
import { exit } from './identify/auth';

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
				if (path.startsWith('/exit')) return await exit(request, env);
				if (path.startsWith('/problem')) return await mfdkx();
				if (path.startsWith('/encrypted')) return await slymt();
				if (path.startsWith('/file.ico')) return await bkcez();
				return await ydmzk(request);
			} else {
				return path.startsWith('/api')
					? await pyenv(request)
					: await baydc(request);
			}
		} catch (error) {
			return await handleError(error);
		}
	}
}