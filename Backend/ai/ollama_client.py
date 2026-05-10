"""
Ollama API Client
Connects to local Ollama instance for AI-powered analysis
"""

import requests
import json
from typing import Optional, Dict, Any


class OllamaClient:
    """Client for interacting with Ollama API"""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        """
        Initialize Ollama client
        
        Args:
            base_url: Ollama API base URL
            model: Model to use (default: llama3.2)
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = 120  # 2 minutes timeout for AI processing
    
    def check_health(self) -> bool:
        """
        Check if Ollama is running and accessible
        
        Returns:
            bool: True if Ollama is healthy, False otherwise
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Ollama health check failed: {e}")
            return False
    
    def list_models(self) -> list:
        """
        List available models
        
        Returns:
            list: Available models
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return [model['name'] for model in data.get('models', [])]
            return []
        except Exception as e:
            print(f"Failed to list models: {e}")
            return []
    
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> Optional[str]:
        """
        Generate completion from Ollama
        
        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate
        
        Returns:
            str: Generated text or None if failed
        """
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            }
            
            if system_prompt:
                payload["system"] = system_prompt
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('response', '').strip()
            else:
                print(f"Ollama API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            print("Ollama request timed out")
            return None
        except Exception as e:
            print(f"Ollama generation failed: {e}")
            return None
    
    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3
    ) -> Optional[Dict[str, Any]]:
        """
        Generate JSON response from Ollama
        
        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            temperature: Sampling temperature (lower for more consistent JSON)
        
        Returns:
            dict: Parsed JSON response or None if failed
        """
        response = self.generate(prompt, system_prompt, temperature)
        
        if not response:
            return None
        
        try:
            # Try to extract JSON from response
            # Sometimes LLMs wrap JSON in markdown code blocks
            if '```json' in response:
                json_str = response.split('```json')[1].split('```')[0].strip()
            elif '```' in response:
                json_str = response.split('```')[1].split('```')[0].strip()
            else:
                json_str = response.strip()
            
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON response: {e}")
            print(f"Response was: {response}")
            return None
    
    def pull_model(self, model_name: Optional[str] = None) -> bool:
        """
        Pull/download a model
        
        Args:
            model_name: Model to pull (default: self.model)
        
        Returns:
            bool: True if successful
        """
        model = model_name or self.model
        
        try:
            print(f"Pulling model {model}... This may take a few minutes.")
            response = requests.post(
                f"{self.base_url}/api/pull",
                json={"name": model},
                stream=True,
                timeout=600  # 10 minutes for model download
            )
            
            if response.status_code == 200:
                # Stream progress
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line)
                        if 'status' in data:
                            print(f"  {data['status']}")
                
                print(f"✓ Model {model} pulled successfully")
                return True
            else:
                print(f"Failed to pull model: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Failed to pull model: {e}")
            return False


# Global instance
_ollama_client = None


def get_ollama_client() -> OllamaClient:
    """Get global Ollama client instance"""
    global _ollama_client
    if _ollama_client is None:
        _ollama_client = OllamaClient()
    return _ollama_client
