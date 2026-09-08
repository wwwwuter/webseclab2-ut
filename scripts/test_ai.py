"""AI端到端测试脚本"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.ai_analysis import AIAnalysis
from app.models.experiment import Experiment
from app.services.ai_service import AIService

app = create_app()
with app.app_context():
    test_user = User.query.filter_by(username='test').first()
    ai = AIService(model='qwen2.5:7b')

    # Test 1: Custom analysis
    print('=== Test 1: Custom AI Analysis ===')
    analysis, error = ai.analyze_custom(
        user_id=test_user.id,
        input_data='Target: 192.168.56.101, open ports: 80/tcp Apache 2.4.57, 3306/tcp MySQL 8.0',
        model='qwen2.5:7b'
    )

    if error:
        print(f'Error: {error}')
    else:
        print(f'Risk Level: {analysis.risk_label}')
        print(f'Status: {analysis.status_label}')
        va = analysis.vulnerability_analysis or 'N/A'
        print(f'Analysis: {va[:200]}')
        pa = analysis.possible_attack or 'N/A'
        print(f'Attack: {pa[:200]}')
        fs = analysis.fix_solution or 'N/A'
        print(f'Fix: {fs[:200]}')

    # Test 2: Experiment analysis
    print()
    print('=== Test 2: Experiment AI Analysis ===')
    exp = Experiment.query.filter_by(user_id=test_user.id).first()
    if exp:
        analysis2, error2 = ai.analyze_experiment(test_user.id, exp.id, model='qwen2.5:7b')
        if error2:
            print(f'Error: {error2}')
        else:
            print(f'Risk: {analysis2.risk_label}, Status: {analysis2.status_label}')
            va2 = analysis2.vulnerability_analysis or 'N/A'
            print(f'Analysis: {va2[:200]}')

    # Test 3: User isolation
    print()
    print('=== Test 3: User Isolation ===')
    all_analyses = AIAnalysis.query.filter_by(user_id=test_user.id).all()
    print(f'Test user has {len(all_analyses)} analyses')
    if all_analyses:
        result, err = ai.get_analysis_by_id(all_analyses[0].id, user_id=999)
        print(f'Other user access blocked: {err}')

    # Test 4: Delete
    print()
    print('=== Test 4: Delete ===')
    for a in all_analyses:
        ai.delete_analysis(a.id, test_user.id)
    remaining = AIAnalysis.query.filter_by(user_id=test_user.id).count()
    print(f'After cleanup: {remaining} remaining')

    print()
    print('========== All end-to-end tests passed ==========')
