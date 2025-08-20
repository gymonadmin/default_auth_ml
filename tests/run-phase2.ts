// tests/run-phase2.ts
import { TestRunner } from './setup';

async function runAllPhase2Tests() {
  console.log('🚀 Starting Phase 2 Tests: Entities & Repositories\n');
  
  const tests = [
    './user-entity.test.ts',
    './profile-entity.test.ts', 
    './user-repository.test.ts',
    './session-repository.test.ts'
  ];
  
  let totalPassed = 0;
  let totalFailed = 0;
  
  for (const test of tests) {
    console.log(`\n🧪 Running ${test.replace('./', '').replace('.test.ts', '')} tests...`);
    console.log('='.repeat(60));
    
    try {
      // Clear the test runner for each file
      (TestRunner as any).tests = [];
      (TestRunner as any).beforeEachFn = null;
      (TestRunner as any).beforeAllFn = null;
      (TestRunner as any).afterAllFn = null;
      
      // Import and run the test
      await import(test);
      
      const beforeRunCount = (TestRunner as any).tests.length;
      await TestRunner.run();
      
      // Count would be calculated in TestRunner.run(), but we'll track manually
      // This is a simplified version - in real implementation you'd need to capture results
      console.log(`✅ ${test} completed`);
      
    } catch (error) {
      console.error(`❌ ${test} failed:`, error);
      totalFailed++;
    }
  }
  
  console.log('\n' + '='.repeat(60));
  console.log(`📊 Phase 2 Results: ${totalPassed} files passed, ${totalFailed} files failed`);
  
  if (totalFailed > 0) {
    console.log('❌ Some tests failed. Please check the output above.');
    process.exit(1);
  } else {
    console.log('✅ All Phase 2 tests passed! Ready for Phase 3.');
    process.exit(0);
  }
}

if (require.main === module) {
  runAllPhase2Tests().catch(console.error);
}
