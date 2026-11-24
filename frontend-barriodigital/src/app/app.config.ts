import { ApplicationConfig, inject, provideAppInitializer, provideZoneChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { catchError, of } from 'rxjs';
import { AuthInterceptor } from './interceptors/auth.interceptor';
import {
  MsalBroadcastService,
  MsalGuard,
  MsalGuardConfiguration,
  MsalInterceptor,
  MsalInterceptorConfiguration,
  MsalService,
  MSAL_GUARD_CONFIG,
  MSAL_INSTANCE,
  MSAL_INTERCEPTOR_CONFIG
} from '@azure/msal-angular';
import {
  BrowserCacheLocation,
  IPublicClientApplication,
  InteractionType,
  LogLevel,
  PublicClientApplication
} from '@azure/msal-browser';
import { routes } from './app.routes';
import { environment } from '../environments/environment';

export function loggerCallback(logLevel: LogLevel, message: string) {
  // console.log(message);
}

export function MSALInstanceFactory(): IPublicClientApplication {
  let currentOrigin = (typeof window !== 'undefined' && window.location && window.location.origin)
    ? window.location.origin
    : environment.azureAd.redirectUri.replace(/\/$/, '');

  // Microsoft Entra ID exige estrictamente HTTPS para cualquier IP o dominio externo (no localhost)
  if (!currentOrigin.includes('localhost') && currentOrigin.startsWith('http://')) {
    currentOrigin = currentOrigin.replace('http://', 'https://');
  }

  const dynamicRedirectUri = `${currentOrigin}/`;
  const dynamicPostLogoutUri = `${currentOrigin}/login`;

  return new PublicClientApplication({
    auth: {
      clientId: environment.azureAd.clientId,
      authority: `https://login.microsoftonline.com/${environment.azureAd.tenantId}`,
      redirectUri: dynamicRedirectUri,
      postLogoutRedirectUri: dynamicPostLogoutUri
    },
    cache: {
      cacheLocation: BrowserCacheLocation.LocalStorage,
      storeAuthStateInCookie: false
    },
    system: {
      loggerOptions: {
        loggerCallback,
        logLevel: LogLevel.Warning,
        piiLoggingEnabled: false
      }
    }
  });
}

export function MSALInterceptorConfigFactory(): MsalInterceptorConfiguration {
  const protectedResourceMap = new Map<string, Array<string>>();
  // Asocia automáticamente las llamadas al API Gateway de AWS con el scope del IDaaS de Azure AD
  protectedResourceMap.set(`${environment.apiGatewayUrl}/api/*`, [environment.azureAd.apiScope]);

  return {
    interactionType: InteractionType.Popup,
    protectedResourceMap
  };
}

export function MSALGuardConfigFactory(): MsalGuardConfiguration {
  return {
    interactionType: InteractionType.Popup,
    authRequest: {
      scopes: ['user.read', environment.azureAd.apiScope]
    }
  };
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideAppInitializer(() => {
      const msalService = inject(MsalService);
      return msalService.initialize().pipe(
        catchError((err: any) => {
          console.warn('MSAL initialization warning handled:', err);
          return of(undefined);
        })
      );
    }),
    provideRouter(routes),
    provideHttpClient(withInterceptorsFromDi()),
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    },
    {
      provide: MSAL_INSTANCE,
      useFactory: MSALInstanceFactory
    },
    {
      provide: MSAL_GUARD_CONFIG,
      useFactory: MSALGuardConfigFactory
    },
    {
      provide: MSAL_INTERCEPTOR_CONFIG,
      useFactory: MSALInterceptorConfigFactory
    },
    MsalService,
    MsalGuard,
    MsalBroadcastService
  ]
};
