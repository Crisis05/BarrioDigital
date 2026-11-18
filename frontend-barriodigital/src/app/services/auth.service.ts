import { Injectable, inject } from '@angular/core';
import { MsalService, MsalBroadcastService } from '@azure/msal-angular';
import { EventMessage, EventType, InteractionStatus, AuthenticationResult, AccountInfo } from '@azure/msal-browser';
import { BehaviorSubject, Observable, finalize, filter, tap } from 'rxjs';
import { environment } from '../../environments/environment';

export interface UserProfile {
  name: string;
  email: string;
  username: string;
  roles: string[];
  isDemoUser?: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private msalService = inject(MsalService);
  private msalBroadcastService = inject(MsalBroadcastService);

  private currentUserSubject = new BehaviorSubject<UserProfile | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  private isAuthenticatingSubject = new BehaviorSubject<boolean>(false);
  public isAuthenticating$ = this.isAuthenticatingSubject.asObservable();

  constructor() {
    this.initMsalListener();
    this.checkCurrentAccount();
  }

  private initMsalListener(): void {
    this.msalBroadcastService.msalSubject$
      .pipe(
        filter((msg: EventMessage) =>
          msg.eventType === EventType.LOGIN_SUCCESS ||
          msg.eventType === EventType.ACQUIRE_TOKEN_SUCCESS
        )
      )
      .subscribe((result: EventMessage) => {
        const payload = result.payload as AuthenticationResult;
        if (payload && payload.account) {
          this.msalService.instance.setActiveAccount(payload.account);
          this.extractAndSetUser(payload.account);
        }
      });

    this.msalBroadcastService.inProgress$
      .pipe(filter((status: InteractionStatus) => status === InteractionStatus.None))
      .subscribe(() => {
        this.checkCurrentAccount();
      });
  }

  public checkCurrentAccount(): void {
    const activeAccount = this.msalService.instance.getActiveAccount();
    if (activeAccount) {
      this.extractAndSetUser(activeAccount);
    } else {
      const accounts = this.msalService.instance.getAllAccounts();
      if (accounts.length > 0) {
        this.msalService.instance.setActiveAccount(accounts[0]);
        this.extractAndSetUser(accounts[0]);
      }
    }
  }

  private extractAndSetUser(account: AccountInfo): void {
    const idTokenClaims = account.idTokenClaims as Record<string, any> || {};
    // Los roles en Azure AD se devuelven en el claim 'roles'
    let roles: string[] = [];
    if (Array.isArray(idTokenClaims['roles'])) {
      roles = idTokenClaims['roles'];
    } else if (typeof idTokenClaims['roles'] === 'string') {
      roles = [idTokenClaims['roles']];
    } else {
      // Si no tiene roles asignados aun en Azure, por defecto Vecino
      roles = ['Vecino'];
    }

    const profile: UserProfile = {
      name: account.name || account.username || 'Usuario',
      email: account.username,
      username: account.username,
      roles: roles,
      isDemoUser: false
    };

    this.currentUserSubject.next(profile);
  }

  public login(): Observable<AuthenticationResult> {
    this.isAuthenticatingSubject.next(true);
    return this.msalService.loginPopup({
      scopes: ['user.read', environment.azureAd.apiScope]
    }).pipe(
      tap((result: AuthenticationResult) => {
        this.msalService.instance.setActiveAccount(result.account);
        this.extractAndSetUser(result.account);
      }),
      finalize(() => this.isAuthenticatingSubject.next(false))
    );
  }

  public logout(): void {
    this.currentUserSubject.next(null);
    this.msalService.logoutPopup({
      postLogoutRedirectUri: environment.azureAd.postLogoutRedirectUri
    }).subscribe();
  }

  public async getAccessToken(): Promise<string | null> {
    const current = this.currentUserSubject.value;
    if (current?.isDemoUser) {
      return 'demo-token-' + current.roles.join('-');
    }

    const account = this.msalService.instance.getActiveAccount();
    if (!account) return null;

    try {
      const response = await this.msalService.instance.acquireTokenSilent({
        account: account,
        scopes: [environment.azureAd.apiScope]
      });
      return response.accessToken;
    } catch {
      return null;
    }
  }

  public hasRole(role: string): boolean {
    const user = this.currentUserSubject.value;
    if (!user) return false;
    return user.roles.some(r => r.toLowerCase() === role.toLowerCase());
  }

  public hasAnyRole(roles: string[]): boolean {
    return roles.some(role => this.hasRole(role));
  }

  public getCurrentUser(): UserProfile | null {
    return this.currentUserSubject.value;
  }

  /**
   * Permite alternar roles para revision docente y pruebas funcionales completas
   */
  public setDemoRole(role: 'Admin' | 'Funcionario' | 'Vecino' | 'Auditor'): void {
    const demoProfiles: Record<string, UserProfile> = {
      Admin: {
        name: 'Carlos Mendoza (Administrador)',
        email: 'carlos.admin@barriodigital.cl',
        username: 'carlos.admin',
        roles: ['Admin'],
        isDemoUser: true
      },
      Funcionario: {
        name: 'Mariana González (Funcionario)',
        email: 'mariana.operaciones@barriodigital.cl',
        username: 'mariana.funcionario',
        roles: ['Funcionario'],
        isDemoUser: true
      },
      Vecino: {
        name: 'Roberto Salgado (Vecino)',
        email: 'roberto.salgado@gmail.com',
        username: 'roberto.vecino',
        roles: ['Vecino'],
        isDemoUser: true
      },
      Auditor: {
        name: 'Verónica Valenzuela (Auditora)',
        email: 'veronica.auditoria@barriodigital.cl',
        username: 'veronica.auditor',
        roles: ['Auditor'],
        isDemoUser: true
      }
    };

    const profile = demoProfiles[role];
    if (profile) {
      this.currentUserSubject.next(profile);
    }
  }
}
