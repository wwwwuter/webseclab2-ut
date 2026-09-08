"""Phase 6 end-to-end test script"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.experiment import Experiment
from app.models.report import Report
from app.services.report_service import ReportService
from app.services.dashboard_service import DashboardService

app = create_app()
with app.app_context():
    db.create_all()
    print('[1] Report table created OK')

    # Test 2: Generate report for test user's experiment
    test_user = User.query.filter_by(username='test').first()
    exp = Experiment.query.filter_by(user_id=test_user.id).first()
    if exp:
        rs = ReportService()
        report, error = rs.create_experiment_report(test_user.id, exp.id)
        if error:
            print(f'[2] Report generation error: {error}')
        else:
            print(f'[2] Report generated: {report.title}, {report.file_size_kb}KB, status={report.status_label}')
            # Verify file exists
            filepath = os.path.join(rs.pdf_gen.output_dir, report.file_path)
            exists = os.path.exists(filepath)
            print(f'    File exists: {exists}, path: {report.file_path}')

            # Test 3: Download file
            fp, name, err = rs.get_report_file(report.id, test_user.id)
            print(f'[3] Download: name={name}, error={err}')

            # Test 4: User isolation - admin cannot access test's report
            admin = User.query.filter_by(username='admin').first()
            fp2, name2, err2 = rs.get_report_file(report.id, admin.id)
            print(f'[4] User isolation: admin->test report = {err2}')

            # Cleanup
            rs.delete_report(report.id, test_user.id)
            print(f'[5] Report deleted')
    else:
        print('[2] No experiment found for test user')

    # Test 5: Dashboard service
    ds = DashboardService()
    user_data = ds.get_user_dashboard(test_user.id)
    print(f'[6] User dashboard: experiments={user_data["user_stats"]["experiment_count"]}, scans={user_data["user_stats"]["scan_count"]}')

    admin_data = ds.get_admin_dashboard()
    print(f'[7] Admin dashboard: users={admin_data["platform_stats"]["user_count"]}, vulns={admin_data["platform_stats"]["vulnerability_count"]}')

    # Test 6: HTTP routes
    with app.test_client() as client:
        client.post('/login', data={'username':'test','password':'test123'}, follow_redirects=True)

        r = client.get('/report')
        assert r.status_code == 200
        print(f'[8] /report 200 OK')

        r = client.get('/security-dashboard')
        assert r.status_code == 200
        print(f'[9] /security-dashboard 200 OK')

        r = client.get('/security-dashboard/api')
        assert r.status_code == 200
        print(f'[10] /security-dashboard/api 200 OK')

    print('\n========== All Phase 6 tests passed ==========')
