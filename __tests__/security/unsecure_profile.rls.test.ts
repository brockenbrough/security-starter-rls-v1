/**
 * "BEFORE" table: unsecure_profile is a copy of myapp_profile that is left
 * WITHOUT Row Level Security on purpose (see supabase/schema.sql).
 *
 * These tests are expected to FAIL, now and after myapp_profile is fixed, so
 * students can compare the two tables side by side.
 */
import { describeRlsSuite } from './rls-suite';

describeRlsSuite('unsecure_profile');
