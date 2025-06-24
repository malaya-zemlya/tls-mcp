"""
Integration tests for TLS MCP Server

These tests verify the server can start and handle basic operations
"""

import pytest
import asyncio
import tempfile
from pathlib import Path

from tls_mcp_server.main import main, server


class TestIntegration:
    """Integration tests for the MCP server"""
    
    def test_server_starts_without_error(self):
        """Test that the server can be imported and created without errors"""
        # This test verifies the server module loads correctly
        assert server.name == "tls-mcp-server"
        
        # Verify server is the correct type
        from mcp.server import Server
        assert isinstance(server, Server)
    
    @pytest.mark.asyncio
    async def test_tools_registration(self):
        """Test that tools are properly registered"""
        from tls_mcp_server.main import list_tools
        
        tools = await list_tools()
        
        # Should have 1 tool (the new unified fetch_certificate)
        assert len(tools) == 1
        assert tools[0].name == "fetch_certificate"
        
        # Verify tool has proper schema with new options
        tool = tools[0]
        assert tool.inputSchema is not None
        assert 'type' in tool.inputSchema
        assert tool.inputSchema['type'] == 'object'
        assert 'properties' in tool.inputSchema
        
        # Check for new properties
        properties = tool.inputSchema['properties']
        expected_properties = ["hostname", "port", "include_pem", "analyze", "lint", "use_openssl"]
        for prop in expected_properties:
            assert prop in properties