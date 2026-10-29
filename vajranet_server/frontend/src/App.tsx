import { Routes, Route, Navigate, useLocation, useParams } from "react-router-dom";
import { lazy, Suspense, useEffect } from "react";
import { ForcePasswordChangeProvider } from "./context/ForcePasswordChangeContext";
import { ToastProvider } from "./context/ToastContext";
import { useToast } from "./context/useToast";
import { ConfirmDialogProvider } from "./context/ConfirmDialogContext";
import { LiveWebSocketProvider } from "./context/LiveWebSocketContext";
import { AuthStatusProvider } from "./context/AuthStatusContext";
import { RateLimitProvider } from "./context/RateLimitContext";
import ErrorBoundary from "./components/ErrorBoundary";
import RateLimitBanner from "./components/RateLimitBanner";
import { LoadingScreen } from "@/components/ui/loading";
import { RULE_ENGINE_ENABLED } from "./lib/featureFlags";

// This page was renamed — send returning users to the new location, with a
// one-time toast so a saved bookmark or muscle memory doesn't feel silently broken.
const RenamedRouteRedirect = ({ to, message }: { to: string; message: string }) => {
  const { showToast } = useToast();
  useEffect(() => {
    showToast(message, "info");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return <Navigate to={to} replace />;
};

// Lazy load components for routes
const LoginForm = lazy(() => import("./pages/login/index.tsx"));
const SignUpForm = lazy(() => import("./pages/Signup"));
const Dashboard = lazy(() => import("./pages/Dashboard/index.tsx"));
const DashboardLayout = lazy(() => import("./components/layout/Layout"));
const ProtectedRoute = lazy(() => import("./components/ProtectedRoute"));
const SuperAdminRoute = lazy(() => import("./components/SuperAdminRoute"));
const PublicRoute = lazy(() => import("./components/PublicRoute"));
const UpdateProfile = lazy(() => import("./features/Settings/UpdateProfile"));
const Settings = lazy(() => import("./features/Settings/Settings"));
const NodesView = lazy(() => import("./features/Nodes/NodesView/index.tsx"));
const Alerts = lazy(() => import("./features/Alerts/index"));
const AlertsView = lazy(() => import("./features/Alerts/AlertsView/index.tsx"));
const Compliance = lazy(() => import("./features/Compliance/index"));
const MyDevices = lazy(() => import("./features/MyDevices/index"));
const MyTeam = lazy(() => import("./features/MyTeam/index"));
const PolicyManagement = lazy(() => import("./features/PolicyManagement/index"));
const NotificationLogs = lazy(() => import("./features/NotificationLogs/index"));
const Help = lazy(() => import("./features/Help/index"));
const AIAssistant = lazy(() => import("./features/AI/index"));
const ThreatHunting = lazy(() => import("./features/ThreatHunting/index"));
const QueryEditor = lazy(() => import("./features/ThreatHunting/QueryEditor"));
const Network = lazy(() => import("./features/Network/index"));
const VulnerabilityManagement = lazy(() => import("./features/VulnerabilityManagement/index"));
const CveDetailPage = lazy(() => import("./features/VulnerabilityManagement/CveDetailPage"));
const DomainReputation = lazy(() => import("./features/DomainReputation/index"));
const FileIntegrity = lazy(() => import("./features/FileIntegrity/index"));
const RuleEngine = lazy(() => import("./features/RuleEngine/index"));
const DataRetention = lazy(() => import("./features/DataRetention/index"));
const Analytics = lazy(() => import("./features/Analytics/index.tsx"));
const NotFound = lazy(() => import("./components/NotFound"));
const PageLoader = () => <LoadingScreen size="full" className="bg-gray-50" />;

// Param-preserving redirect for the pre-consolidation CVE detail URL —
// /software-vulnerabilities/:cve -> /vulnerability-management/:cve. A plain
// <Navigate to="/vulnerability-management" /> would drop the deep link.
const SoftwareVulnerabilitiesCveRedirect = () => {
  const { cve } = useParams<{ cve: string }>();
  return <Navigate to={`/vulnerability-management/${encodeURIComponent(cve ?? '')}`} replace />;
};

// Assets moved from its own route into the Vulnerability Scanner tab's
// OpenVAS sub-view (see features/VulnerabilityScanner/index.tsx's OpenVASTab/
// OPENVAS_TABS and features/Assets/index.tsx) — asset identity resolution is
// OpenVAS-only, so it lives between that view's own "Scans" and "Settings"
// tabs rather than as a top-level Network Security tab. Same param-preserving
// reasoning as SoftwareVulnerabilitiesCveRedirect above, but landing on a
// nested tab + query param instead of a path segment.
const AssetDetailRedirect = () => {
  const { assetUuid } = useParams<{ assetUuid: string }>();
  return (
    <Navigate
      to={`/network?tab=vuln&scanner=openvas&openvasTab=assets&assetUuid=${encodeURIComponent(assetUuid ?? '')}`}
      replace
    />
  );
};

const App = () => {
  const location = useLocation();

  return (
    <ToastProvider>
      <RateLimitProvider>
      <ConfirmDialogProvider>
      <AuthStatusProvider>
        <ForcePasswordChangeProvider>
          <LiveWebSocketProvider>
              <div>
                <RateLimitBanner />
                <ErrorBoundary resetKey={`${location.pathname}${location.search}`}>
                  <Suspense fallback={<PageLoader />}>
                    <Routes>
                      {/* Public routes - redirect authenticated users to dashboard */}
                      <Route
                        path="/"
                        element={
                          <PublicRoute>
                            <LoginForm />
                          </PublicRoute>
                        }
                      />
                      <Route
                        path="/new-user"
                        element={
                          <ProtectedRoute>
                            <SuperAdminRoute>
                              <SignUpForm />
                            </SuperAdminRoute>
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/login"
                        element={
                          <PublicRoute>
                            <LoginForm />
                          </PublicRoute>
                        }
                      />
                      <Route
                        element={
                          <ProtectedRoute>
                            <DashboardLayout />
                          </ProtectedRoute>
                        }
                      >
                        <Route path="/dashboard" element={<Dashboard />} />
                        <Route path="/update-profile" element={<UpdateProfile />} />
                        <Route path="/settings" element={<Settings />} />
                        <Route path="/nodes/view/:host_identifier" element={<NodesView />} />
                        <Route path="/alerts" element={<Alerts />} />
                        <Route path="/alerts/view" element={<AlertsView />} />
                        <Route path="/compliance" element={<Compliance />} />
                        <Route
                          path="/audit-trail"
                          element={
                            <SuperAdminRoute>
                              <NotificationLogs />
                            </SuperAdminRoute>
                          }
                        />
                        <Route
                          path="/notifications"
                          element={<RenamedRouteRedirect to="/audit-trail" message="Notifications is now called Audit Trail." />}
                        />
                        <Route path="/my-devices" element={<MyDevices />} />
                        <Route
                          path="/management"
                          element={
                            <SuperAdminRoute>
                              <MyTeam />
                            </SuperAdminRoute>
                          }
                        />
                        <Route
                          path="/remote-actions"
                          element={<RenamedRouteRedirect to="/policy-management" message="Remote Actions is now called Policy Management." />}
                        />
                        <Route
                          path="/policy-management"
                          element={
                            <SuperAdminRoute allowedRoles={['Group Admin']}>
                              <PolicyManagement />
                            </SuperAdminRoute>
                          }
                        />
                        <Route
                          path="/file-integrity"
                          element={
                            <SuperAdminRoute allowedRoles={['Group Admin']}>
                              <FileIntegrity />
                            </SuperAdminRoute>
                          }
                        />
                        <Route path="/help" element={<Help />} />
                        <Route path="/ai" element={<AIAssistant />} />
                        {import.meta.env.VITE_DEPLOYMENT_MODE !== 'cloud' && (
                        <Route
                          path="/network"
                          element={
                            <SuperAdminRoute allowedRoles={['Group Admin']}>
                              <Network />
                            </SuperAdminRoute>
                          }
                        />
                        )}
                        {/* Asset identity resolution now lives inside Network Security's
                            Vulnerability Scanner tab, in the OpenVAS sub-view's own tab bar
                            (features/VulnerabilityScanner/index.tsx, between "Scans" and
                            "Settings"), not a route of its own — these two graceful redirects
                            cover a link/bookmark to the old standalone /assets page, mirroring
                            RenamedRouteRedirect and SoftwareVulnerabilitiesCveRedirect above.
                            Access control happens when /network itself loads (SuperAdminRoute
                            allowedRoles={['Group Admin']} below), which is already exactly
                            routes/api/assets.ts's [checkJwt, requireAdmin] gate. */}
                        <Route
                          path="/assets"
                          element={<RenamedRouteRedirect to="/network?tab=vuln&scanner=openvas&openvasTab=assets" message="Assets now lives inside Network Security's Vulnerability Scanner tab." />}
                        />
                        <Route path="/assets/:assetUuid" element={<AssetDetailRedirect />} />
                        {/* Deliberately tighter than the backend: routes/api/vulnerabilities.ts
                            gates its three endpoints with only checkAccessJwt + apiDataLimiter
                            (no requireAdmin/requireSuperAdmin — node-group scoping is enforced
                            per-query instead), so any authenticated role including Viewer can
                            already fetch this fleet CVE data directly via the API. This plain
                            <SuperAdminRoute> takes no allowedRoles, unlike /policy-management,
                            /network above, so a Group Admin or Viewer has no UI
                            path to it at all. Fails safe (the UI is stricter than the API, not
                            looser) — left as-is pending an explicit product decision on the
                            intended audience, rather than silently loosening RBAC-adjacent
                            routing. */}
                        <Route
                          path="/vulnerability-management"
                          element={
                            <SuperAdminRoute>
                              <VulnerabilityManagement />
                            </SuperAdminRoute>
                          }
                        />
                        <Route
                          path="/vulnerability-management/:cve"
                          element={
                            <SuperAdminRoute>
                              <CveDetailPage />
                            </SuperAdminRoute>
                          }
                        />
                        {/* Graceful redirects for the pre-consolidation URL — same pattern as
                            /remote-actions -> /policy-management and /notifications ->
                            /audit-trail above. */}
                        <Route path="/software-vulnerabilities" element={<Navigate to="/vulnerability-management" replace />} />
                        <Route path="/software-vulnerabilities/:cve" element={<SoftwareVulnerabilitiesCveRedirect />} />
                        <Route
                          path="/domain-reputation"
                          element={
                            <SuperAdminRoute allowedRoles={['Group Admin']}>
                              <DomainReputation />
                            </SuperAdminRoute>
                          }
                        />
                        {/* Detection/correlation rules are exactly the "changes detection/
                            enforcement behavior" class of sensitive action per
                            docs/RULE_ENGINE_UI_SPEC.md — same page-level gate as
                            /domain-reputation, /policy-management, /network above
                            (Super Administrator or Group Admin; a plain Viewer has no UI
                            path to it). Per-action write authorization (add/enable-disable/
                            delete a rule, push a live reload, import a CSV, add/edit a
                            threat-intel feed) is enforced server-side by Vajranet-BE's
                            backend/src/routes/api/rule-engine.ts, not by this route gate
                            alone. */}
                        <Route
                          path="/rule-engine"
                          element={
                            RULE_ENGINE_ENABLED ? (
                              <SuperAdminRoute allowedRoles={['Group Admin']}>
                                <RuleEngine />
                              </SuperAdminRoute>
                            ) : (
                              <Navigate to="/dashboard" replace />
                            )
                          }
                        />
                        <Route
                          path="/data-retention"
                          element={
                            <SuperAdminRoute>
                              <DataRetention />
                            </SuperAdminRoute>
                          }
                        />
                        {/* Mirrors the /grafana/ gate in
                            controllers/auth/validateGrafana.ts. A Group Admin
                            sees only their own groups' nodes — the dashboards
                            filter on the viewer's email. A Viewer is excluded
                            and would otherwise reach the page only to get a
                            bare 403 from nginx inside the iframe. */}
                        <Route
                          path="/analytics"
                          element={
                            <SuperAdminRoute allowedRoles={['Group Admin']}>
                              <Analytics />
                            </SuperAdminRoute>
                          }
                        />
                        <Route path="/threat-hunting" element={<ThreatHunting />} />
                        <Route path="/threat-hunting/new" element={<QueryEditor />} />
                        <Route path="/threat-hunting/:id" element={<QueryEditor />} />
                      </Route>
                      <Route path="*" element={<NotFound />} />
                    </Routes>
                  </Suspense>
                </ErrorBoundary>
              </div>
          </LiveWebSocketProvider>
        </ForcePasswordChangeProvider>
      </AuthStatusProvider>
      </ConfirmDialogProvider>
      </RateLimitProvider>
    </ToastProvider>
  );
};

export default App;
