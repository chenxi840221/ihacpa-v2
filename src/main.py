"""
Main Entry Point for IHACPA v2.0

AI-Enhanced Python Package Security Automation System
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional
import traceback

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from .config import ConfigManager
from .cli import parse_arguments
from .core.app_controller import AppController
from .core.error_handler import ErrorHandler, ErrorCategory, ErrorSeverity


class IHACPAApplication:
    """Main IHACPA application class"""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.app_controller: Optional[AppController] = None
        
    async def run(self) -> int:
        """
        Main application entry point.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Parse command line arguments
            args = parse_arguments()
            
            # Load configuration
            config = self._load_configuration(args)
            if not config:
                return 1
            
            # Apply command line overrides
            self._apply_cli_overrides(config, args)
            
            # Execute command
            return await self._execute_command(args, config)
            
        except KeyboardInterrupt:
            print("\n⚠️  Operation cancelled by user")
            return 130
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            if '--debug' in sys.argv:
                traceback.print_exc()
            return 1
    
    def _load_configuration(self, args) -> Optional[object]:
        """Load application configuration"""
        try:
            config_path = getattr(args, 'config', None)
            config = self.config_manager.load_config(config_path)
            
            # Validate configuration
            is_valid, errors = self.config_manager.validate_config()
            if not is_valid:
                print("❌ Configuration validation failed:")
                for error in errors:
                    print(f"   • {error}")
                return None
            
            return config
            
        except Exception as e:
            print(f"❌ Configuration error: {e}")
            return None
    
    def _apply_cli_overrides(self, config, args):
        """Apply command line argument overrides to configuration"""
        # Debug mode
        if getattr(args, 'debug', False):
            config.app.debug_mode = True
            config.logging.level = "DEBUG"
        
        # Quiet mode
        if getattr(args, 'quiet', False):
            config.logging.console_output = False
        
        # Verbose mode
        if getattr(args, 'verbose', False):
            config.logging.level = "DEBUG"
        
        # AI-related overrides for scan command
        if hasattr(args, 'no_ai') and args.no_ai:
            config.ai.enabled = False
        
        if hasattr(args, 'no_correlation') and args.no_correlation:
            config.ai.correlation_analysis_enabled = False
        
        if hasattr(args, 'no_risk_assessment') and args.no_risk_assessment:
            config.ai.risk_assessment_enabled = False
    
    async def _execute_command(self, args, config) -> int:
        """Execute the specified command"""
        command = args.command
        
        if command == 'scan':
            return await self._execute_scan_command(args, config)
        elif command == 'report':
            return await self._execute_report_command(args, config)
        elif command == 'config':
            return self._execute_config_command(args, config)
        elif command == 'test':
            return await self._execute_test_command(args, config)
        else:
            print(f"❌ Unknown command: {command}")
            return 1
    
    async def _execute_scan_command(self, args, config) -> int:
        """Execute scan command with enhanced columns processing (default)"""
        try:
            print(f"🚀 Starting IHACPA v{config.app.version} with Enhanced Columns")
            print(f"📊 Input file: {args.excel_file}")
            print(f"🔧 Enhanced columns: {', '.join(config.excel.enhanced_columns)}")
            
            if args.dry_run:
                print("🔍 Running in DRY-RUN mode (no file modifications)")
            
            # Create and setup application controller (now with enhanced processing by default)
            self.app_controller = AppController(config, dry_run=args.dry_run)
            
            # Setup application
            setup_success = await self.app_controller.setup(
                input_file=args.excel_file,
                output_file=getattr(args, 'output', None)
            )
            
            if not setup_success:
                print("❌ Application setup failed")
                return 1
            
            # Execute enhanced scanning (columns E, F, K, L, M, W processing)
            print("🚀 Starting enhanced vulnerability scanning...")
            print("   • Column E: Publication dates from PyPI")
            print("   • Column F: Latest version comparison")  
            print("   • Column K: GitHub repository URLs")
            print("   • Column L: GitHub security advisory URLs") 
            print("   • Column M: GitHub security analysis (AI/Browser/Sandbox)")
            print("   • Column W: IHACPA recommendations")
            
            scan_success = await self.app_controller.scan_packages(
                package_names=getattr(args, 'packages', None),
                start_row=getattr(args, 'start_row', None),
                end_row=getattr(args, 'end_row', None)
            )
            
            if not scan_success:
                print("❌ Enhanced scanning failed")
                return 1
            
            # Generate enhanced reports
            print("📊 Generating enhanced reports...")
            report_success = await self.app_controller.generate_reports()
            
            if not report_success:
                print("⚠️  Some report generation steps failed")
            
            # Print enhanced summary
            self._print_enhanced_scan_summary()
            
            print("✅ IHACPA enhanced scan completed successfully!")
            return 0
            
        except Exception as e:
            print(f"❌ Scan command failed: {e}")
            if config.app.debug_mode:
                traceback.print_exc()
            return 1
        finally:
            if self.app_controller:
                await self.app_controller.cleanup()
    
    async def _execute_report_command(self, args, config) -> int:
        """Execute report command"""
        try:
            from .io.report_generator import ReportGenerator
            import json
            
            print(f"📊 Generating reports from: {args.input_file}")
            
            # Load scan results
            with open(args.input_file, 'r', encoding='utf-8') as f:
                scan_results = json.load(f)
            
            # Create report generator
            report_generator = ReportGenerator(config)
            
            # Set output directory
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate reports based on format
            if args.format in ['txt', 'all']:
                summary_path = report_generator.generate_summary_report(
                    scan_results, output_dir / "summary_report.txt"
                )
                print(f"📄 Summary report: {summary_path}")
            
            if args.format in ['json', 'all']:
                json_path = report_generator.generate_json_report(
                    scan_results, output_dir / "detailed_report.json"
                )
                print(f"📄 JSON report: {json_path}")
            
            print("✅ Report generation completed!")
            return 0
            
        except Exception as e:
            print(f"❌ Report command failed: {e}")
            if config.app.debug_mode:
                traceback.print_exc()
            return 1
    
    def _execute_config_command(self, args, config) -> int:
        """Execute config command"""
        try:
            if args.config_action == 'init':
                # Initialize configuration file
                success = self.config_manager.save_config(args.path)
                if success:
                    print(f"✅ Configuration initialized: {args.path}")
                    return 0
                else:
                    print("❌ Failed to initialize configuration")
                    return 1
            
            elif args.config_action == 'validate':
                # Validate configuration file
                temp_manager = ConfigManager(args.config_file)
                temp_config = temp_manager.load_config()
                is_valid, errors = temp_manager.validate_config()
                
                if is_valid:
                    print(f"✅ Configuration is valid: {args.config_file}")
                    return 0
                else:
                    print(f"❌ Configuration validation failed: {args.config_file}")
                    for error in errors:
                        print(f"   • {error}")
                    return 1
            
            else:
                print("❌ Unknown config action")
                return 1
                
        except Exception as e:
            print(f"❌ Config command failed: {e}")
            return 1
    
    async def _execute_test_command(self, args, config) -> int:
        """Execute test command"""
        try:
            from .core.sandbox_manager import SandboxManager
            from .io.excel_handler import ExcelHandler
            
            print("🧪 Running IHACPA system tests")
            
            all_passed = True
            
            # Test AI service
            if args.ai or args.all:
                print("\n🤖 Testing AI service connection...")
                if config.ai.enabled:
                    # Test AI factory
                    try:
                        from .ai_layer.chain_factory import AIChainFactory
                        factory = AIChainFactory(config.ai.__dict__)
                        if factory.test_connection():
                            print("   ✅ AI service connection successful")
                        else:
                            print("   ❌ AI service connection failed")
                            all_passed = False
                    except Exception as e:
                        print(f"   ❌ AI service test failed: {e}")
                        all_passed = False
                else:
                    print("   ⚠️  AI service disabled in configuration")
            
            # Test sandboxes
            if args.sandboxes or args.all:
                print("\n🔍 Testing sandbox health...")
                try:
                    sandbox_manager = SandboxManager(config.__dict__)
                    await sandbox_manager.initialize()
                    
                    health = await sandbox_manager.health_check_all()
                    for sandbox, is_healthy in health.items():
                        status = "✅" if is_healthy else "❌"
                        print(f"   {status} {sandbox}: {'healthy' if is_healthy else 'unhealthy'}")
                        if not is_healthy:
                            all_passed = False
                    
                    await sandbox_manager.cleanup()
                except Exception as e:
                    print(f"   ❌ Sandbox test failed: {e}")
                    all_passed = False
            
            # Test Excel file
            if args.excel or args.all:
                excel_file = args.excel if args.excel else "testcases/data/2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
                print(f"\n📊 Testing Excel file reading: {excel_file}")
                try:
                    if Path(excel_file).exists():
                        excel_handler = ExcelHandler(excel_file, config)
                        if excel_handler.load_workbook():
                            is_valid, errors = excel_handler.validate_file_structure()
                            if is_valid:
                                package_count = excel_handler.get_package_count()
                                print(f"   ✅ Excel file valid, {package_count} packages found")
                            else:
                                print("   ❌ Excel file validation failed:")
                                for error in errors:
                                    print(f"      • {error}")
                                all_passed = False
                        else:
                            print("   ❌ Failed to load Excel file")
                            all_passed = False
                        excel_handler.close()
                    else:
                        print(f"   ⚠️  Excel test file not found: {excel_file}")
                except Exception as e:
                    print(f"   ❌ Excel test failed: {e}")
                    all_passed = False
            
            # Summary
            print(f"\n{'✅ All tests passed!' if all_passed else '❌ Some tests failed!'}")
            return 0 if all_passed else 1
            
        except Exception as e:
            print(f"❌ Test command failed: {e}")
            if config.app.debug_mode:
                traceback.print_exc()
            return 1
    
    def _print_enhanced_scan_summary(self):
        """Print enhanced scan result summary"""
        if not self.app_controller:
            return
        
        summary = self.app_controller.get_processing_summary()
        
        print("\n" + "=" * 70)
        print("📊 ENHANCED SCAN RESULTS SUMMARY")
        print("=" * 70)
        print(f"📦 Packages processed: {summary['packages_processed']}")
        print(f"✅ Successful: {summary['packages_successful']}")
        print(f"❌ Failed: {summary['packages_failed']}")
        print(f"📈 Success rate: {summary['success_rate']:.1f}%")
        
        # Enhanced columns information
        print(f"🔧 Enhanced columns: {', '.join(summary['columns_processed'])}")
        print(f"🚀 Enhanced processing: ENABLED")
        
        if summary['ai_enhanced']:
            print("🤖 AI enhancements: ENABLED")
        else:
            print("🤖 AI enhancements: DISABLED (using mock)")
        
        if not summary.get('dry_run', False):
            print(f"📄 Output file: {summary['output_file']}")
            if summary['backup_file']:
                print(f"💾 Backup file: {summary['backup_file']}")
        
        print("\n📋 Enhanced Features Applied:")
        print("   • Column E: Publication dates extracted from PyPI")
        print("   • Column F: Latest versions compared with current")
        print("   • Column K: GitHub repository URLs extracted")
        print("   • Column L: GitHub security advisory URLs generated")
        print("   • Column M: GitHub security analysis performed")
        print("   • Column W: IHACPA recommendations generated")
        
    def _print_scan_summary(self):
        """Legacy scan result summary (fallback)"""
        # Redirect to enhanced summary
        self._print_enhanced_scan_summary()


def main():
    """Main entry point"""
    app = IHACPAApplication()
    try:
        exit_code = asyncio.run(app.run())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(130)


if __name__ == "__main__":
    main()