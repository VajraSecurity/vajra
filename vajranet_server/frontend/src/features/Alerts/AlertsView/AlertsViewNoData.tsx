/**
 * AlertsView: Shown when no alert data is in route state.
 */

import { Link } from 'react-router-dom';

const AlertsViewNoData = () => {
  return (
    <div className="min-h-screen bg-[#f8f9fb]">
      <div className="flex flex-col items-center justify-center min-h-[50vh] px-4">
        <p className="text-gray-600 mb-4">No alert data to view. Refer to the list of alerts first.</p>
        <Link
          to="/alerts"
          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700"
        >
          <i className="fa fa-arrow-left" /> Back to Alerts
        </Link>
      </div>
    </div>
  );
};

export default AlertsViewNoData;
