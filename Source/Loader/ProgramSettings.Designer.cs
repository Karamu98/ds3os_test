﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Loader {
    
    
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator", "16.8.1.0")]
    internal sealed partial class ProgramSettings : global::System.Configuration.ApplicationSettingsBase {
        
        private static ProgramSettings defaultInstance = ((ProgramSettings)(global::System.Configuration.ApplicationSettingsBase.Synchronized(new ProgramSettings())));
        
        public static ProgramSettings Default {
            get {
                return defaultInstance;
            }
        }
        
        [global::System.Configuration.UserScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("")]
        public string exe_location {
            get {
                return ((string)(this["exe_location"]));
            }
            set {
                this["exe_location"] = value;
            }
        }
        
        [global::System.Configuration.UserScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("")]
        public string server_config_json {
            get {
                return ((string)(this["server_config_json"]));
            }
            set {
                this["server_config_json"] = value;
            }
        }
    }
}
