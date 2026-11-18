/**
 * "AFTER" table: myapp_profile is the table the class will lock down with RLS.
 *
 * Today these tests FAIL (RLS is off). After RLS is enabled with correct
 * policies, they should all PASS.
 */
import { describeRlsSuite } from './rls-suite';

describeRlsSuite('myapp_profile');
